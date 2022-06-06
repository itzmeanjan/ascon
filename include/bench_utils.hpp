#pragma once
#include "accel_ascon.hpp"
#include <iomanip>
#include <sstream>

#define MSG_LEN 4096ul // per work-item input message length ( bytes )
#define AD_LEN 64ul    // per work-item input associated data length ( bytes )
#define CT_LEN 4096ul // per work-item input plain/ cipher text length ( bytes )

#define GB 1073741824. // 1 << 30 bytes
#define MB 1048576.    // 1 << 20 bytes
#define KB 1024.       // 1 << 10 bytes

// Choose which data-parallel ascon variant to benchmark
enum ascon_variant
{
  ascon_hash,
  ascon_hashA,
  ascon_128_encrypt,
  ascon_128_decrypt,
  ascon_128a_encrypt,
  ascon_128a_decrypt,
  ascon_80pq_encrypt,
  ascon_80pq_decrypt,
};

// Function prototype declaration
//
// Executes accelerated Ascon-{Hash, HashA, 128, 128a} kernels `itr_cnt` -many
// times and computes average execution time of following SYCL
// commands ( returned back in order ), in nanosecond level granularity
//
// - host -> device input tx time ( total )
// - kernel execution time
// - device -> host input tx time ( total )
void
exec_kernel(sycl::queue&,
            const size_t,
            const size_t,
            const size_t,
            const ascon_variant,
            double* const);

// Time execution of SYCL command, whose submission resulted into given SYCL
// event, in nanosecond level granularity
//
// Ensure SYCL queue, onto which command was submitted, has profiling enabled !
static inline uint64_t
time_event(sycl::event& evt)
{
  // type aliasing because I wanted to keep them all single line
  using u64 = sycl::cl_ulong;
  using prof_t = sycl::info::event_profiling;

  const prof_t BEG = prof_t::command_start;
  const prof_t END = prof_t::command_end;

  const u64 beg = evt.get_profiling_info<BEG>();
  const u64 end = evt.get_profiling_info<END>();

  return static_cast<uint64_t>(end - beg);
}

// Convert how many bytes processed in how long timespan ( given in nanosecond
// level granularity ) to more human digestable
// format ( i.e. GB/ s or MB/ s or KB/ s or B/ s )
static inline const std::string
to_readable_bandwidth(const size_t bytes, // bytes
                      const double ts     // nanoseconds
)
{
  const double bytes_ = static_cast<double>(bytes);
  const double ts_ = ts * 1e-9;    // seconds
  const double bps = bytes_ / ts_; // bytes/ sec

  std::stringstream ss;
  ss << std::setprecision(2);

  bps >= GB   ? ss << (bps / GB) << " GB/ s"
  : bps >= MB ? ss << (bps / MB) << " MB/ s"
  : bps >= KB ? ss << (bps / KB) << " KB/ s"
              : ss << bps << " B/ s";
  return ss.str();
}

void
exec_kernel(sycl::queue& q,
            const size_t wi_cnt,
            const size_t wg_size,
            const size_t itr_cnt,
            const ascon_variant av,
            double* const ts)
{
  // must enable queue profiling !
  assert(q.has_property<sycl::property::queue::enable_profiling>());

  // type aliasing so that I type lesser
  using evt = sycl::event;
  using evts = std::vector<sycl::event>;

  constexpr size_t ts_size = sizeof(uint64_t) * 3;

  // allocate memory on host ( for keeping exec time of enqueued commands )
  uint64_t* ts_sum = static_cast<uint64_t*>(std::malloc(ts_size));

  // so that average execution/ data transfer time can be safely computed !
  std::memset(ts_sum, 0, ts_size);

  for (size_t i = 0; i < itr_cnt; i++) {
    using namespace accel_ascon;

    // dispatch Ascon-Hash/ Ascon-Hasha kernel
    if (av == ascon_variant::ascon_hash || av == ascon_variant::ascon_hashA) {
      // each work item to consume `MSG_LEN` -bytes
      const size_t m_len = MSG_LEN * wi_cnt;
      // each work-item to produce 32 -bytes digest
      const size_t d_len = wi_cnt << 5;

      // input message bytes on accelerator
      uint8_t* msg_d = static_cast<uint8_t*>(sycl::malloc_device(m_len, q));
      // input message bytes on host
      uint8_t* msg_h = static_cast<uint8_t*>(sycl::malloc_host(m_len, q));
      // output digest bytes on accelerator
      uint8_t* dig_d = static_cast<uint8_t*>(sycl::malloc_device(d_len, q));
      // output digest bytes on host
      uint8_t* dig_h = static_cast<uint8_t*>(sycl::malloc_host(d_len, q));

      // prepare random messge bytes on host
      ascon_utils::random_data(msg_h, m_len);

      // copy input message bytes to accelerator
      evt e0 = q.memcpy(msg_d, msg_h, m_len);
      evt e1 = q.memset(dig_d, 0, d_len);
      evt e2 = q.memset(dig_h, 0, d_len);

      evts e3{ e0, e1 };
      evt e4;

      if (av == ascon_variant::ascon_hash) {
        e4 = hash(q, msg_d, m_len, dig_d, d_len, wi_cnt, wg_size, e3);
      } else if (av == ascon_variant::ascon_hashA) {
        e4 = hash_a(q, msg_d, m_len, dig_d, d_len, wi_cnt, wg_size, e3);
      }

      evt e5 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e2, e4 });
        h.memcpy(dig_h, dig_d, d_len);
      });

      e5.wait(); // host synchronization

      ts_sum[0] += time_event(e0); // host -> device data tx time
      ts_sum[1] += time_event(e4); // kernel execution time
      ts_sum[2] += time_event(e5); // device -> host data tx time

      // release all resources managed by SYCL runtime
      sycl::free(msg_d, q);
      sycl::free(msg_h, q);
      sycl::free(dig_d, q);
      sycl::free(dig_h, q);

    }
    // dispatch Ascon-128/ Ascon-128a encryption kernel
    else if (av == ascon_variant::ascon_128_encrypt ||
             av == ascon_variant::ascon_128a_encrypt) {
      // each work-item to encrypt `CT_LEN` -bytes plain text
      // and will produce same number of cipher text bytes
      const size_t ct_len = CT_LEN * wi_cnt;
      // each work-item to consume `AD_LEN` -bytes associated data
      const size_t ad_len = AD_LEN * wi_cnt;
      // secret key, nonce & authentication tag --- all are each of 16 -bytes
      // wide; each work-item to use single secret key, nonce & produce
      // single authentication tag
      const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt;

      // plain text memory allocated on accelerator
      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // plain text memory allocated on host
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // encrypted text memory allocated on accelerator
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // encrypted text memory allocated on host
      uint8_t* e_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // associated data memory allocated on accelerator
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      // associated data memory allocated on host
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      // secret key memory allocated on accelerator
      uint8_t* k_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // secret key memory allocated on host
      uint8_t* k_h = static_cast<uint8_t*>(sycl::malloc_host(knt_len, q));
      // pubic message nonce memory allocated on accelerator
      uint8_t* n_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // pubic message nonce memory allocated on host
      uint8_t* n_h = static_cast<uint8_t*>(sycl::malloc_host(knt_len, q));
      // authentication tag memory allocated on accelerator
      uint8_t* t_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // authentication tag memory allocated on host
      uint8_t* t_h = static_cast<uint8_t*>(sycl::malloc_host(knt_len, q));

      // generate random plain text on host
      ascon_utils::random_data(p_h, ct_len);
      // generate random associated data on host
      ascon_utils::random_data(a_h, ad_len);
      // generate random secret keys on host
      ascon_utils::random_data(k_h, knt_len);
      // generate random public message nonces on host
      ascon_utils::random_data(n_h, knt_len);

      // copy plain text to accelerator memory
      evt e0 = q.memcpy(p_d, p_h, ct_len);
      // copy associated data to accelerator memory
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      // copy secret keys to accelerator memory
      evt e2 = q.memcpy(k_d, k_h, knt_len);
      // copy public message nonces to accelerator memory
      evt e3 = q.memcpy(n_d, n_h, knt_len);

      evt e4 = q.memset(e_d, 0, ct_len);
      evt e5 = q.memset(e_h, 0, ct_len);
      evt e6 = q.memset(t_d, 0, knt_len);
      evt e7 = q.memset(t_h, 0, knt_len);
      evt e8;

      if (av == ascon_variant::ascon_128_encrypt) {
        e8 = encrypt_128(q,
                         k_d,
                         knt_len,
                         n_d,
                         knt_len,
                         a_d,
                         ad_len,
                         p_d,
                         ct_len,
                         e_d,
                         ct_len,
                         t_d,
                         knt_len,
                         wi_cnt,
                         wg_size,
                         { e0, e1, e2, e3, e4, e6 });
      } else if (av == ascon_variant::ascon_128a_encrypt) {
        e8 = encrypt_128a(q,
                          k_d,
                          knt_len,
                          n_d,
                          knt_len,
                          a_d,
                          ad_len,
                          p_d,
                          ct_len,
                          e_d,
                          ct_len,
                          t_d,
                          knt_len,
                          wi_cnt,
                          wg_size,
                          { e0, e1, e2, e3, e4, e6 });
      }

      // copy cipher text back to host
      evt e9 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e5, e8 });
        h.memcpy(e_h, e_d, ct_len);
      });

      // copy authentication tags back to host
      evt e10 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e7, e8 });
        h.memcpy(t_h, t_d, knt_len);
      });

      evt e11 = q.ext_oneapi_submit_barrier({ e9, e10 });

      e11.wait(); // host synchronization

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3);

      // host -> device data tx time
      ts_sum[0] += (ts0 + ts1);
      // kernel execution time
      ts_sum[1] += time_event(e8);
      // device -> host data tx time
      ts_sum[2] += (time_event(e9) + time_event(e10));

      // deallocate all resources which are managed by SYCL runtime
      sycl::free(p_d, q);
      sycl::free(p_h, q);
      sycl::free(e_d, q);
      sycl::free(e_h, q);
      sycl::free(a_d, q);
      sycl::free(a_h, q);
      sycl::free(k_d, q);
      sycl::free(k_h, q);
      sycl::free(n_d, q);
      sycl::free(n_h, q);
      sycl::free(t_d, q);
      sycl::free(t_h, q);
    }
    // dispatch Ascon-128/ Ascon-128a decryption kernel
    else if (av == ascon_variant::ascon_128_decrypt ||
             av == ascon_variant::ascon_128a_decrypt) {
      // each work-item to decrypt `CT_LEN` -bytes and produce same number of
      // plain text bytes
      const size_t ct_len = CT_LEN * wi_cnt;
      // each work-item to consume `AD_LEN` -bytes associated data
      const size_t ad_len = AD_LEN * wi_cnt;
      // secret key, nonce & authentication tags --- all are 16 -bytes wide
      const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt;
      // each work-item to write single boolean flag back to global memory,
      // denoting status of verified decryption process
      const size_t flg_len = sizeof(bool) * wi_cnt;

      // plain text memory allocated on accelerator
      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // plain text memory allocated on host
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // encrypted text memory allocated on accelerator
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // decrypted text memory allocated on accelerator
      uint8_t* d_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // decrypted text memory allocated on host
      uint8_t* d_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // associated data memory allocated on accelerator
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      // associated data memory allocated on host
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      // secret key memory allocated on accelerator
      uint8_t* k_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // secret key memory allocated on host
      uint8_t* k_h = static_cast<uint8_t*>(sycl::malloc_host(knt_len, q));
      // pubic message nonce memory allocated on accelerator
      uint8_t* n_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // pubic message nonce memory allocated on host
      uint8_t* n_h = static_cast<uint8_t*>(sycl::malloc_host(knt_len, q));
      // authentication tag memory allocated on accelerator
      uint8_t* t_d = static_cast<uint8_t*>(sycl::malloc_device(knt_len, q));
      // verified decryption status flags, allocated on accelerator
      bool* f_d = static_cast<bool*>(sycl::malloc_device(flg_len, q));
      // verified decryption status flags, allocated on host
      bool* f_h = static_cast<bool*>(sycl::malloc_host(flg_len, q));

      // generate random plain text on host
      ascon_utils::random_data(p_h, ct_len);
      // generate random associated data on host
      ascon_utils::random_data(a_h, ad_len);
      // generate random secret keys on host
      ascon_utils::random_data(k_h, knt_len);
      // generate random public message nonces on host
      ascon_utils::random_data(n_h, knt_len);

      // copy plain text to accelerator memory
      evt e0 = q.memcpy(p_d, p_h, ct_len);
      // copy associated data to accelerator memory
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      // copy secret keys to accelerator memory
      evt e2 = q.memcpy(k_d, k_h, knt_len);
      // copy public message nonces to accelerator memory
      evt e3 = q.memcpy(n_d, n_h, knt_len);

      evt e4 = q.memset(e_d, 0, ct_len);
      evt e5 = q.memset(t_d, 0, knt_len);
      evt e6 = q.memset(d_d, 0, ct_len);
      evt e7 = q.memset(d_h, 0, ct_len);
      evt e8 = q.memset(f_d, 0, flg_len);
      evt e9 = q.memset(f_h, 0, flg_len);
      evt e11;

      // first encrypt then decrypt; while timing command execution ignore
      // time required to compute encrypted data & authentication tags
      if (av == ascon_variant::ascon_128_decrypt) {
        evt e10 = encrypt_128(q,
                              k_d,
                              knt_len,
                              n_d,
                              knt_len,
                              a_d,
                              ad_len,
                              p_d,
                              ct_len,
                              e_d,
                              ct_len,
                              t_d,
                              knt_len,
                              wi_cnt,
                              wg_size,
                              { e0, e1, e2, e3, e4, e5 });
        e11 = decrypt_128(q,
                          k_d,
                          knt_len,
                          n_d,
                          knt_len,
                          a_d,
                          ad_len,
                          e_d,
                          ct_len,
                          t_d,
                          knt_len,
                          d_d,
                          ct_len,
                          f_d,
                          flg_len,
                          wi_cnt,
                          wg_size,
                          { e6, e8, e10 });
      } else if (av == ascon_variant::ascon_128a_decrypt) {
        evt e10 = encrypt_128a(q,
                               k_d,
                               knt_len,
                               n_d,
                               knt_len,
                               a_d,
                               ad_len,
                               p_d,
                               ct_len,
                               e_d,
                               ct_len,
                               t_d,
                               knt_len,
                               wi_cnt,
                               wg_size,
                               { e0, e1, e2, e3, e4, e5 });
        e11 = decrypt_128a(q,
                           k_d,
                           knt_len,
                           n_d,
                           knt_len,
                           a_d,
                           ad_len,
                           e_d,
                           ct_len,
                           t_d,
                           knt_len,
                           d_d,
                           ct_len,
                           f_d,
                           flg_len,
                           wi_cnt,
                           wg_size,
                           { e6, e8, e10 });
      }

      evt e12 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e7, e11 });
        h.memcpy(d_h, d_d, ct_len);
      });

      evt e13 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e9, e11 });
        h.memcpy(f_h, f_d, flg_len);
      });

      evt e14 = q.ext_oneapi_submit_barrier({ e12, e13 });

      e14.wait();

      // ensure that verified decryption occurred !
      for (size_t j = 0; j < wi_cnt; j++) {
        assert(f_h[j]);
      }

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3) * 2;

      // host -> device data tx time
      ts_sum[0] += (ts0 + ts1);
      // Ascon-{128,128a} decryption kernel execution time
      ts_sum[1] += time_event(e11);
      // device -> host data tx time
      ts_sum[2] += (time_event(e12) + time_event(e13));

      // release all resources which are managed by SYCL runtime
      sycl::free(p_d, q);
      sycl::free(p_h, q);
      sycl::free(e_d, q);
      sycl::free(d_d, q);
      sycl::free(d_h, q);
      sycl::free(a_d, q);
      sycl::free(a_h, q);
      sycl::free(k_d, q);
      sycl::free(k_h, q);
      sycl::free(n_d, q);
      sycl::free(n_h, q);
      sycl::free(t_d, q);
      sycl::free(f_d, q);
      sycl::free(f_h, q);
    }
    // dispatch Ascon-80pq encryption kernel
    else if (av == ascon_variant::ascon_80pq_encrypt) {
      // each work-item to encrypt `CT_LEN` -bytes plain text
      // and will produce same number of cipher text bytes
      const size_t ct_len = CT_LEN * wi_cnt;
      // each work-item to consume `AD_LEN` -bytes associated data
      const size_t ad_len = AD_LEN * wi_cnt;
      // secret keys are 20 -bytes wide; each work-item to use single secret key
      const size_t k_len = 20ul * wi_cnt;
      // public message nonce & authentication tag --- each of 16 -bytes
      // wide; each work-item to use single nonce & produce single
      // authentication tag
      const size_t nt_len = (sizeof(uint64_t) << 1) * wi_cnt;

      // plain text memory allocated on accelerator
      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // plain text memory allocated on host
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // encrypted text memory allocated on accelerator
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // encrypted text memory allocated on host
      uint8_t* e_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // associated data memory allocated on accelerator
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      // associated data memory allocated on host
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      // secret key memory allocated on accelerator
      uint8_t* k_d = static_cast<uint8_t*>(sycl::malloc_device(k_len, q));
      // secret key memory allocated on host
      uint8_t* k_h = static_cast<uint8_t*>(sycl::malloc_host(k_len, q));
      // pubic message nonce memory allocated on accelerator
      uint8_t* n_d = static_cast<uint8_t*>(sycl::malloc_device(nt_len, q));
      // pubic message nonce memory allocated on host
      uint8_t* n_h = static_cast<uint8_t*>(sycl::malloc_host(nt_len, q));
      // authentication tag memory allocated on accelerator
      uint8_t* t_d = static_cast<uint8_t*>(sycl::malloc_device(nt_len, q));
      // authentication tag memory allocated on host
      uint8_t* t_h = static_cast<uint8_t*>(sycl::malloc_host(nt_len, q));

      // generate random plain text on host
      ascon_utils::random_data(p_h, ct_len);
      // generate random associated data on host
      ascon_utils::random_data(a_h, ad_len);
      // generate random secret keys on host
      ascon_utils::random_data(k_h, k_len);
      // generate random public message nonces on host
      ascon_utils::random_data(n_h, nt_len);

      // copy plain text to accelerator memory
      evt e0 = q.memcpy(p_d, p_h, ct_len);
      // copy associated data to accelerator memory
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      // copy secret keys to accelerator memory
      evt e2 = q.memcpy(k_d, k_h, k_len);
      // copy public message nonces to accelerator memory
      evt e3 = q.memcpy(n_d, n_h, nt_len);

      evt e4 = q.memset(e_d, 0, ct_len);
      evt e5 = q.memset(e_h, 0, ct_len);
      evt e6 = q.memset(t_d, 0, nt_len);
      evt e7 = q.memset(t_h, 0, nt_len);

      evt e8 = encrypt_80pq(q,
                            k_d,
                            k_len,
                            n_d,
                            nt_len,
                            a_d,
                            ad_len,
                            p_d,
                            ct_len,
                            e_d,
                            ct_len,
                            t_d,
                            nt_len,
                            wi_cnt,
                            wg_size,
                            { e0, e1, e2, e3, e4, e6 });

      // copy cipher text back to host
      evt e9 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e5, e8 });
        h.memcpy(e_h, e_d, ct_len);
      });

      // copy authentication tags back to host
      evt e10 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e7, e8 });
        h.memcpy(t_h, t_d, nt_len);
      });

      evt e11 = q.ext_oneapi_submit_barrier({ e9, e10 });

      e11.wait(); // host synchronization

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3);

      // host -> device data tx time
      ts_sum[0] += (ts0 + ts1);
      // kernel execution time
      ts_sum[1] += time_event(e8);
      // device -> host data tx time
      ts_sum[2] += (time_event(e9) + time_event(e10));

      // deallocate all resources which are managed by SYCL runtime
      sycl::free(p_d, q);
      sycl::free(p_h, q);
      sycl::free(e_d, q);
      sycl::free(e_h, q);
      sycl::free(a_d, q);
      sycl::free(a_h, q);
      sycl::free(k_d, q);
      sycl::free(k_h, q);
      sycl::free(n_d, q);
      sycl::free(n_h, q);
      sycl::free(t_d, q);
      sycl::free(t_h, q);
    }
    // dispatch Ascon-80pq decryption kernel
    else if (av == ascon_variant::ascon_80pq_decrypt) {
      // each work-item to decrypt `CT_LEN` -bytes and produce same number of
      // plain text bytes
      const size_t ct_len = CT_LEN * wi_cnt;
      // each work-item to consume `AD_LEN` -bytes associated data
      const size_t ad_len = AD_LEN * wi_cnt;
      // each secret key of 20 -bytes
      const size_t k_len = 20ul * wi_cnt;
      // public message nonce & authentication tags --- all are 16 -bytes wide
      const size_t nt_len = (sizeof(uint64_t) << 1) * wi_cnt;
      // each work-item to write single boolean flag back to global memory,
      // denoting status of verified decryption process
      const size_t flg_len = sizeof(bool) * wi_cnt;

      // plain text memory allocated on accelerator
      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // plain text memory allocated on host
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // encrypted text memory allocated on accelerator
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // decrypted text memory allocated on accelerator
      uint8_t* d_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      // decrypted text memory allocated on host
      uint8_t* d_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      // associated data memory allocated on accelerator
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      // associated data memory allocated on host
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      // secret key memory allocated on accelerator
      uint8_t* k_d = static_cast<uint8_t*>(sycl::malloc_device(k_len, q));
      // secret key memory allocated on host
      uint8_t* k_h = static_cast<uint8_t*>(sycl::malloc_host(k_len, q));
      // pubic message nonce memory allocated on accelerator
      uint8_t* n_d = static_cast<uint8_t*>(sycl::malloc_device(nt_len, q));
      // pubic message nonce memory allocated on host
      uint8_t* n_h = static_cast<uint8_t*>(sycl::malloc_host(nt_len, q));
      // authentication tag memory allocated on accelerator
      uint8_t* t_d = static_cast<uint8_t*>(sycl::malloc_device(nt_len, q));
      // verified decryption status flags, allocated on accelerator
      bool* f_d = static_cast<bool*>(sycl::malloc_device(flg_len, q));
      // verified decryption status flags, allocated on host
      bool* f_h = static_cast<bool*>(sycl::malloc_host(flg_len, q));

      // generate random plain text on host
      ascon_utils::random_data(p_h, ct_len);
      // generate random associated data on host
      ascon_utils::random_data(a_h, ad_len);
      // generate random secret keys on host
      ascon_utils::random_data(k_h, k_len);
      // generate random public message nonces on host
      ascon_utils::random_data(n_h, nt_len);

      // copy plain text to accelerator memory
      evt e0 = q.memcpy(p_d, p_h, ct_len);
      // copy associated data to accelerator memory
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      // copy secret keys to accelerator memory
      evt e2 = q.memcpy(k_d, k_h, k_len);
      // copy public message nonces to accelerator memory
      evt e3 = q.memcpy(n_d, n_h, nt_len);

      evt e4 = q.memset(e_d, 0, ct_len);
      evt e5 = q.memset(t_d, 0, nt_len);
      evt e6 = q.memset(d_d, 0, ct_len);
      evt e7 = q.memset(d_h, 0, ct_len);
      evt e8 = q.memset(f_d, 0, flg_len);
      evt e9 = q.memset(f_h, 0, flg_len);

      // first encrypt then decrypt; while timing command execution ignores
      // time required to compute encrypted data & authentication tags
      evt e10 = encrypt_80pq(q,
                             k_d,
                             k_len,
                             n_d,
                             nt_len,
                             a_d,
                             ad_len,
                             p_d,
                             ct_len,
                             e_d,
                             ct_len,
                             t_d,
                             nt_len,
                             wi_cnt,
                             wg_size,
                             { e0, e1, e2, e3, e4, e5 });

      evt e11 = decrypt_80pq(q,
                             k_d,
                             k_len,
                             n_d,
                             nt_len,
                             a_d,
                             ad_len,
                             e_d,
                             ct_len,
                             t_d,
                             nt_len,
                             d_d,
                             ct_len,
                             f_d,
                             flg_len,
                             wi_cnt,
                             wg_size,
                             { e6, e8, e10 });

      evt e12 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e7, e11 });
        h.memcpy(d_h, d_d, ct_len);
      });

      evt e13 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e9, e11 });
        h.memcpy(f_h, f_d, flg_len);
      });

      evt e14 = q.ext_oneapi_submit_barrier({ e12, e13 });

      e14.wait();

      // ensure that verified decryption occurred !
      for (size_t j = 0; j < wi_cnt; j++) {
        assert(f_h[j]);
      }

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3) * 2;

      // host -> device data tx time
      ts_sum[0] += (ts0 + ts1);
      // Ascon-{128,128a} decryption kernel execution time
      ts_sum[1] += time_event(e11);
      // device -> host data tx time
      ts_sum[2] += (time_event(e12) + time_event(e13));

      // release all resources which are managed by SYCL runtime
      sycl::free(p_d, q);
      sycl::free(p_h, q);
      sycl::free(e_d, q);
      sycl::free(d_d, q);
      sycl::free(d_h, q);
      sycl::free(a_d, q);
      sycl::free(a_h, q);
      sycl::free(k_d, q);
      sycl::free(k_h, q);
      sycl::free(n_d, q);
      sycl::free(n_h, q);
      sycl::free(t_d, q);
      sycl::free(f_d, q);
      sycl::free(f_h, q);
    }
  }

  for (size_t i = 0; i < 3; i++) {
    ts[i] = static_cast<double>(ts_sum[i]) / static_cast<double>(itr_cnt);
  }

  // deallocate resources
  std::free(ts_sum);
}
