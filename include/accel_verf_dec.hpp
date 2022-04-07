#pragma once
#include "ascon.hpp"
#include <CL/sycl.hpp>

// SYCL accelerated Ascon Light Weight Cryptography ( i.e. authenticated
// encryption, verified decryption and hashing ) Implementation
namespace accel_ascon {

// Given total `N` -bytes input cipher text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous cipher byte slices ( each of
// length `L` -bytes ), this function will data-parallelly decrypt those `M`
// -many independent cipher slices, using Ascon-128, while dispatching `M` -many
// SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For decrypting M -many equal length cipher slices, this function will also
// use M -many secret keys ( each 128 -bit ), nonces ( each 128 -bit ),
// authentication tags ( each 128 -bit ) & equal length associated data slices (
// which are never encrypted but they're associated with respective plain text
// slice during encryption phase, so different associated data should result in
// failure of successful verified decryption process )
//
// After each work-item decrypts its portion of cipher text, both plain text (
// length same as cipher text ) & verification flag ( boolean ) will be
// written to respective ( pre-allocated ) memory locations
//
// Note, on host all M -many verification flags should be tested for truth value
//
// In following setup,
//
// N = {text,cipher}_len
// M = wi_cnt
// L = per_wi_ct_len
// K = wg_size
// M * 16 = sec_key_len
// M * 16 = nonce_len
// M * 16 = tag_len
// M * sizeof(bool) = flag_len
//
// Note, boolean type's size may be other than 1, see `Boolean type` section in
// https://en.cppreference.com/mwiki/index.php?title=cpp/language/types&oldid=138484
static inline sycl::event
decrypt_128(
  sycl::queue& q,
  const uint64_t* const __restrict sec_key, // input
  const size_t sec_key_len,                 // bytes
  const uint64_t* const __restrict nonce,   // input
  const size_t nonce_len,                   // bytes
  const uint8_t* const __restrict a_data,   // input
  const size_t a_data_len,                  // bytes
  const uint8_t* const __restrict cipher,   // input
  const size_t cipher_len,                  // bytes
  const uint64_t* const __restrict tag,     // input
  const size_t tag_len,                     // bytes
  uint8_t* const __restrict text,           // output
  const size_t text_len,                    // bytes
  bool* const __restrict flag,              // output
  const size_t flag_len,                    // bytes
  const size_t wi_cnt,                      // SYCL work-item count
  const size_t wg_size,                     // SYCL work-group size
  const std::vector<sycl::event> evts       // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input cipher text must be equally splitted among all work-items
  assert(cipher_len % wi_cnt == 0);
  // Total plain text length must be equal to cipher text length
  assert(cipher_len == text_len);
  // Each (work-item's) secret key is 16 -bytes ( 128 -bit )
  assert(sec_key_len == (wi_cnt << 4));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == sec_key_len);
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);
  // Keeping each verification flag takes sizeof(bool) -byte
  assert(flag_len == sizeof(bool) * wi_cnt);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input cipher text
  const size_t per_wi_ct_len = cipher_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        // offset for secret key, nonce & authentication tag
        const size_t knt_offset = idx << 1;
        // offset for associated data ( byte array )
        const size_t ad_offset = idx * per_wi_ad_len;
        // offset for cipher/ plain text ( byte array )
        const size_t ct_offset = idx * per_wi_ct_len;

        // wrap secret key the way it's expected by decrypt routine
        const ascon::secret_key_128_t k{ { sec_key[knt_offset + 0],
                                           sec_key[knt_offset + 1] } };
        // wrap nonce the way it's expected by decrypt routine
        const ascon::nonce_t n{ { nonce[knt_offset + 0],
                                  nonce[knt_offset + 1] } };
        // wrap authentication tag the way it's expected by decrypt routine
        const ascon::tag_t t{ { tag[knt_offset + 0], tag[knt_offset + 1] } };

        // each work-item decrypts its portion of cipher text with
        // associated data ( not encrypted ) while using provided secret key,
        // nonce & tag, using Ascon-128 algorithm
        const bool f = ascon::decrypt_128(k,
                                          n,
                                          a_data + ad_offset,
                                          per_wi_ad_len,
                                          cipher + ct_offset,
                                          per_wi_ct_len,
                                          text + ct_offset,
                                          t);

        // write successful verification flag back to respective memory location
        //
        // after transfering flag data back to host, it must be asserted for
        // truth value, otherwise decryption may be successful but not verified
        flag[idx] = f;
      });
  });

  return evt;
}

// Given total `N` -bytes input cipher text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous cipher byte slices ( each of
// length `L` -bytes ), this function will data-parallelly decrypt those `M`
// -many independent cipher slices, using Ascon-128a, while dispatching `M`
// -many SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For decrypting M -many equal length cipher slices, this function will also
// use M -many secret keys ( each 128 -bit ), nonces ( each 128 -bit ),
// authentication tags ( each 128 -bit ) & equal length associated data slices (
// which are never encrypted but they're associated with respective plain text
// slice during encryption phase, so different associated data should result in
// failure of successful verified decryption process )
//
// After each work-item decrypts its portion of cipher text, both plain text (
// length same as cipher text ) & verification flag ( boolean ) will be
// written to respective ( pre-allocated ) memory locations
//
// Note, on host all M -many verification flags should be tested for truth value
//
// In following setup,
//
// N = {text,cipher}_len
// M = wi_cnt
// L = per_wi_ct_len
// K = wg_size
// M * 16 = sec_key_len
// M * 16 = nonce_len
// M * 16 = tag_len
// M * sizeof(bool) = flag_len
//
// Note, boolean type's size may be other than 1, see `Boolean type` section in
// https://en.cppreference.com/mwiki/index.php?title=cpp/language/types&oldid=138484
static inline sycl::event
decrypt_128a(
  sycl::queue& q,
  const uint64_t* const __restrict sec_key, // input
  const size_t sec_key_len,                 // bytes
  const uint64_t* const __restrict nonce,   // input
  const size_t nonce_len,                   // bytes
  const uint8_t* const __restrict a_data,   // input
  const size_t a_data_len,                  // bytes
  const uint8_t* const __restrict cipher,   // input
  const size_t cipher_len,                  // bytes
  const uint64_t* const __restrict tag,     // input
  const size_t tag_len,                     // bytes
  uint8_t* const __restrict text,           // output
  const size_t text_len,                    // bytes
  bool* const __restrict flag,              // output
  const size_t flag_len,                    // bytes
  const size_t wi_cnt,                      // SYCL work-item count
  const size_t wg_size,                     // SYCL work-group size
  const std::vector<sycl::event> evts       // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input cipher text must be equally splitted among all work-items
  assert(cipher_len % wi_cnt == 0);
  // Total plain text length must be equal to cipher text length
  assert(cipher_len == text_len);
  // Each (work-item's) secret key is 16 -bytes ( 128 -bit )
  assert(sec_key_len == (wi_cnt << 4));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == sec_key_len);
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);
  // Keeping each verification flag takes sizeof(bool) -byte
  assert(flag_len == sizeof(bool) * wi_cnt);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input cipher text
  const size_t per_wi_ct_len = cipher_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        // offset for secret key, nonce & authentication tag
        const size_t knt_offset = idx << 1;
        // offset for associated data ( byte array )
        const size_t ad_offset = idx * per_wi_ad_len;
        // offset for cipher/ plain text ( byte array )
        const size_t ct_offset = idx * per_wi_ct_len;

        // wrap secret key the way it's expected by decrypt routine
        const ascon::secret_key_128_t k{ { sec_key[knt_offset + 0],
                                           sec_key[knt_offset + 1] } };
        // wrap nonce the way it's expected by decrypt routine
        const ascon::nonce_t n{ { nonce[knt_offset + 0],
                                  nonce[knt_offset + 1] } };
        // wrap authentication tag the way it's expected by decrypt routine
        const ascon::tag_t t{ { tag[knt_offset + 0], tag[knt_offset + 1] } };

        // each work-item decrypts its portion of cipher text with
        // associated data ( not encrypted ) while using provided secret key,
        // nonce & tag, using Ascon-128a algorithm
        const bool f = ascon::decrypt_128a(k,
                                           n,
                                           a_data + ad_offset,
                                           per_wi_ad_len,
                                           cipher + ct_offset,
                                           per_wi_ct_len,
                                           text + ct_offset,
                                           t);

        // write successful verification flag back to respective memory location
        //
        // after transfering flag data back to host, it must be asserted for
        // truth value, otherwise decryption may be successful but not verified
        flag[idx] = f;
      });
  });

  return evt;
}

// Given total `N` -bytes input cipher text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous cipher byte slices ( each of
// length `L` -bytes ), this function will data-parallelly decrypt those `M`
// -many independent cipher slices, using Ascon-80pq, while dispatching `M`
// -many SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For decrypting M -many equal length cipher slices, this function will also
// use M -many secret keys ( each 160 -bit ), nonces ( each 128 -bit ),
// authentication tags ( each 128 -bit ) & equal length associated data slices (
// which are never encrypted but they're associated with respective plain text
// slice during encryption phase, so different associated data should result in
// failure of successful verified decryption process )
//
// After each work-item decrypts its portion of cipher text, both plain text (
// length same as cipher text ) & verification flag ( boolean ) will be
// written to respective ( pre-allocated ) memory locations
//
// Note, on host all M -many verification flags should be tested for truth value
//
// In following setup,
//
// N = {text,cipher}_len
// M = wi_cnt
// L = per_wi_ct_len
// K = wg_size
// M * 20 = sec_key_len
// M * 16 = nonce_len
// M * 16 = tag_len
// M * sizeof(bool) = flag_len
//
// Note, boolean type's size may be other than 1, see `Boolean type` section in
// https://en.cppreference.com/mwiki/index.php?title=cpp/language/types&oldid=138484
static inline sycl::event
decrypt_80pq(
  sycl::queue& q,
  const uint8_t* const __restrict sec_key, // input
  const size_t sec_key_len,                // bytes
  const uint8_t* const __restrict nonce,   // input
  const size_t nonce_len,                  // bytes
  const uint8_t* const __restrict a_data,  // input
  const size_t a_data_len,                 // bytes
  const uint8_t* const __restrict cipher,  // input
  const size_t cipher_len,                 // bytes
  const uint64_t* const __restrict tag,    // input
  const size_t tag_len,                    // bytes
  uint8_t* const __restrict text,          // output
  const size_t text_len,                   // bytes
  bool* const __restrict flag,             // output
  const size_t flag_len,                   // bytes
  const size_t wi_cnt,                     // SYCL work-item count
  const size_t wg_size,                    // SYCL work-group size
  const std::vector<sycl::event> evts      // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input cipher text must be equally splitted among all work-items
  assert(cipher_len % wi_cnt == 0);
  // Total plain text length must be equal to cipher text length
  assert(cipher_len == text_len);
  // Each (work-item's) secret key is 20 -bytes ( 160 -bit )
  assert(sec_key_len == (wi_cnt * 20));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == (wi_cnt << 4));
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);
  // Keeping each verification flag takes sizeof(bool) -byte
  assert(flag_len == sizeof(bool) * wi_cnt);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input cipher text
  const size_t per_wi_ct_len = cipher_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        // offset for secret key
        const size_t k_offset = idx * 20;
        // offset for public message nonce
        const size_t n_offset = idx << 4;
        // offset for authentication tag
        const size_t t_offset = idx << 1;
        // offset for associated data ( byte array )
        const size_t ad_offset = idx * per_wi_ad_len;
        // offset for cipher/ plain text ( byte array )
        const size_t ct_offset = idx * per_wi_ct_len;

        // wrap secret key the way it's expected by decrypt routine
        ascon::secret_key_160_t k;
        ascon_utils::from_be_bytes(sec_key + k_offset, k);

        // wrap nonce the way it's expected by decrypt routine
        ascon::nonce_t n;
        ascon_utils::from_be_bytes(nonce + n_offset, n);

        // wrap authentication tag the way it's expected by decrypt routine
        const ascon::tag_t t{ { tag[t_offset + 0], tag[t_offset + 1] } };

        // each work-item decrypts its portion of cipher text with
        // associated data ( not encrypted ) while using provided secret key,
        // nonce & tag, using Ascon-80pq algorithm
        const bool f = ascon::decrypt_80pq(k,
                                           n,
                                           a_data + ad_offset,
                                           per_wi_ad_len,
                                           cipher + ct_offset,
                                           per_wi_ct_len,
                                           text + ct_offset,
                                           t);

        // write successful verification flag back to respective memory location
        //
        // after transfering flag data back to host, it must be asserted for
        // truth value, otherwise decryption may be successful but not verified
        flag[idx] = f;
      });
  });

  return evt;
}

}
