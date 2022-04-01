#pragma once
#include "accel_ascon.hpp"
#include <CL/sycl.hpp>

#define MSG_LEN 4096ul // per work-item input message length ( bytes )
#define AD_LEN 64ul    // per work-item input associated data length ( bytes )
#define CT_LEN 4096ul // per work-item input plain/ cipher text length ( bytes )

// Choose which data-parallel ascon variant to benchmark
enum ascon_variant
{
  ascon_hash,
  ascon_hashA,
  ascon_128_encrypt,
  ascon_128_decrypt,
  ascon_128a_encrypt,
  ascon_128a_decrypt,
};

// Function prototype declaration
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
  using u64 = sycl::cl_ulong;
  using prof_t = sycl::info::event_profiling;

  const prof_t BEG = prof_t::command_start;
  const prof_t END = prof_t::command_end;

  const u64 beg = evt.get_profiling_info<BEG>();
  const u64 end = evt.get_profiling_info<END>();

  return static_cast<uint64_t>(end - beg);
}

// Convert nanosecond granularity execution time to readable string i.e. in
// terms of seconds/ milliseconds/ microseconds/ nanoseconds
static inline const std::string
to_readable_timespan(const double ts)
{
  return ts >= 1e9 ? std::to_string(ts * 1e-9) + " s"
                   : ts >= 1e6 ? std::to_string(ts * 1e-6) + " ms"
                               : ts >= 1e3 ? std::to_string(ts * 1e-3) + " us"
                                           : std::to_string(ts) + " ns";
}

// Executes accelerated Ascon-{Hash, HashA, 128, 128a} kernels `itr_cnt` -many
// times and computes average execution time of following SYCL commands
//
// - host -> device input tx time ( total )
// - kernel execution time
// - device -> host input tx time ( total )
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

  using evt = sycl::event;
  using evts = std::vector<sycl::event>;

  constexpr size_t ts_size = sizeof(uint64_t) * 3;

  // allocate memory on host ( for keeping exec time of enqueued commands )
  uint64_t* ts_sum = static_cast<uint64_t*>(std::malloc(ts_size));

  // so that average execution/ data transfer time can be safely computed !
  std::memset(ts_sum, 0, ts_size);

  for (size_t i = 0; i < itr_cnt; i++) {
    using namespace accel_ascon;

    if (av == ascon_variant::ascon_hash || av == ascon_variant::ascon_hashA) {
      const size_t m_len = MSG_LEN * wi_cnt;
      const size_t d_len = wi_cnt << 5;

      uint8_t* msg_d = static_cast<uint8_t*>(sycl::malloc_device(m_len, q));
      uint8_t* msg_h = static_cast<uint8_t*>(sycl::malloc_host(m_len, q));
      uint8_t* dig_d = static_cast<uint8_t*>(sycl::malloc_device(d_len, q));
      uint8_t* dig_h = static_cast<uint8_t*>(sycl::malloc_host(d_len, q));

      ascon_utils::random_data(msg_h, m_len);

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

      e5.wait();

      ts_sum[0] += time_event(e0);
      ts_sum[1] += time_event(e4);
      ts_sum[2] += time_event(e5);

      sycl::free(msg_d, q);
      sycl::free(msg_h, q);
      sycl::free(dig_d, q);
      sycl::free(dig_h, q);
    } else if (av == ascon_variant::ascon_128_encrypt ||
               av == ascon_variant::ascon_128a_encrypt) {
      const size_t ct_len = CT_LEN * wi_cnt;
      const size_t ad_len = AD_LEN * wi_cnt;
      const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt;

      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      uint8_t* e_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      uint64_t* k_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* k_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));
      uint64_t* n_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* n_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));
      uint64_t* t_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* t_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));

      ascon_utils::random_data(p_h, ct_len);
      ascon_utils::random_data(a_h, ad_len);
      ascon_utils::random_data(k_h, wi_cnt << 1);
      ascon_utils::random_data(n_h, wi_cnt << 1);

      evt e0 = q.memcpy(p_d, p_h, ct_len);
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      evt e2 = q.memcpy(k_d, k_h, knt_len);
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

      evt e9 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e5, e8 });
        h.memcpy(e_h, e_d, ct_len);
      });

      evt e10 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e7, e8 });
        h.memcpy(t_h, t_d, knt_len);
      });

      evt e11 = q.ext_oneapi_submit_barrier({ e9, e10 });

      e11.wait();

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3);

      ts_sum[0] += (ts0 + ts1);
      ts_sum[1] += time_event(e8);
      ts_sum[2] += (time_event(e9) + time_event(e10));

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
    } else if (av == ascon_variant::ascon_128_decrypt ||
               av == ascon_variant::ascon_128a_decrypt) {
      const size_t ct_len = CT_LEN * wi_cnt;
      const size_t ad_len = AD_LEN * wi_cnt;
      const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt;
      const size_t flg_len = sizeof(bool) * wi_cnt;

      uint8_t* p_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      uint8_t* p_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      uint8_t* e_d = static_cast<uint8_t*>(sycl::malloc_device(ct_len, q));
      uint8_t* e_h = static_cast<uint8_t*>(sycl::malloc_host(ct_len, q));
      uint8_t* a_d = static_cast<uint8_t*>(sycl::malloc_device(ad_len, q));
      uint8_t* a_h = static_cast<uint8_t*>(sycl::malloc_host(ad_len, q));
      uint64_t* k_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* k_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));
      uint64_t* n_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* n_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));
      uint64_t* t_d = static_cast<uint64_t*>(sycl::malloc_device(knt_len, q));
      uint64_t* t_h = static_cast<uint64_t*>(sycl::malloc_host(knt_len, q));
      bool* f_d = static_cast<bool*>(sycl::malloc_device(flg_len, q));
      bool* f_h = static_cast<bool*>(sycl::malloc_host(flg_len, q));

      ascon_utils::random_data(e_h, ct_len);
      ascon_utils::random_data(a_h, ad_len);
      ascon_utils::random_data(k_h, wi_cnt << 1);
      ascon_utils::random_data(n_h, wi_cnt << 1);
      ascon_utils::random_data(t_h, wi_cnt << 1);

      evt e0 = q.memcpy(e_d, e_h, ct_len);
      evt e1 = q.memcpy(a_d, a_h, ad_len);
      evt e2 = q.memcpy(k_d, k_h, knt_len);
      evt e3 = q.memcpy(n_d, n_h, knt_len);
      evt e4 = q.memcpy(t_d, t_h, knt_len);

      evt e5 = q.memset(p_d, 0, ct_len);
      evt e6 = q.memset(p_h, 0, ct_len);
      evt e7 = q.memset(f_d, 0, flg_len);
      evt e8 = q.memset(f_h, 0, flg_len);
      evt e9;

      if (av == ascon_variant::ascon_128_decrypt) {
        e9 = decrypt_128(q,
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
                         p_d,
                         ct_len,
                         f_d,
                         flg_len,
                         wi_cnt,
                         wg_size,
                         { e0, e1, e2, e3, e4, e5, e7 });
      } else if (av == ascon_variant::ascon_128a_decrypt) {
        e9 = decrypt_128a(q,
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
                          p_d,
                          ct_len,
                          f_d,
                          flg_len,
                          wi_cnt,
                          wg_size,
                          { e0, e1, e2, e3, e4, e5, e7 });
      }

      evt e10 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e6, e9 });
        h.memcpy(p_h, p_d, ct_len);
      });

      evt e11 = q.submit([&](sycl::handler& h) {
        h.depends_on({ e8, e9 });
        h.memcpy(f_h, f_d, flg_len);
      });

      evt e12 = q.ext_oneapi_submit_barrier({ e9, e10 });

      e12.wait();

      const uint64_t ts0 = time_event(e0) + time_event(e1);
      const uint64_t ts1 = time_event(e2) + time_event(e3);

      ts_sum[0] += (ts0 + ts1 + time_event(e4));
      ts_sum[1] += time_event(e9);
      ts_sum[2] += (time_event(e10) + time_event(e11));

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
