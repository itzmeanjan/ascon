#pragma once
#include "ascon.hpp"
#include <CL/sycl.hpp>

// SYCL accelerated Ascon Light Weight Cryptography ( i.e. authenticated
// encryption, verified decryption and hashing ) Implementation
namespace accel_ascon {

// Given total `N` -bytes input plain text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous plain text byte slices ( each of
// length `L` -bytes ), this function will data-parallelly encrypt those `M`
// -many independent text slices, using Ascon-128, while dispatching `M` -many
// SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For encrypting M -many equal length text slices, this function will also use
// M -many secret keys ( each 128 -bit ), nonces ( each 128 -bit ) & equal
// length associated data slices ( which are never encrypted but they're
// associated with respective plain text slice during encryption phase )
//
// After each work-item encrypts its portion of plain text, both ciphered text (
// length same as plain text ) & authentication tag ( 16 -bytes ) will be
// written to respective ( pre-allocated ) memory locations
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
static inline sycl::event
encrypt_128(
  sycl::queue& q,
  const uint8_t* const __restrict sec_key, // input
  const size_t sec_key_len,                // bytes
  const uint8_t* const __restrict nonce,   // input
  const size_t nonce_len,                  // bytes
  const uint8_t* const __restrict a_data,  // input
  const size_t a_data_len,                 // bytes
  const uint8_t* const __restrict text,    // input
  const size_t text_len,                   // bytes
  uint8_t* const __restrict cipher,        // output
  const size_t cipher_len,                 // bytes
  uint8_t* const __restrict tag,           // output
  const size_t tag_len,                    // bytes
  const size_t wi_cnt,                     // SYCL work-item count
  const size_t wg_size,                    // SYCL work-group size
  const std::vector<sycl::event> evts      // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input plain text must be equally splitted among all work-items
  assert(text_len % wi_cnt == 0);
  // Total cipher text length must be equal to plain text length
  assert(text_len == cipher_len);
  // Each (work-item's) secret key is 16 -bytes ( 128 -bit )
  assert(sec_key_len == (wi_cnt << 4));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == sec_key_len);
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input plain text
  const size_t per_wi_ct_len = text_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(sycl::nd_range<1>{ wi_cnt, wg_size },
                   [=](sycl::nd_item<1> it) {
                     const size_t idx = it.get_global_linear_id();

                     // offset for secret key, nonce & authentication tag
                     const size_t knt_offset = idx << 4;
                     // offset for associated data ( byte array )
                     const size_t ad_offset = idx * per_wi_ad_len;
                     // offset for plain/ cipher text ( byte array )
                     const size_t ct_offset = idx * per_wi_ct_len;

                     // wrap secret key the way it's expected by encrypt routine
                     const ascon::secret_key_128_t k{ sec_key + knt_offset };
                     // wrap nonce the way it's expected by encrypt routine
                     const ascon::nonce_t n{ nonce + knt_offset };

                     // each work-item encrypts its portion of plain text (
                     // encrypted ) with associated data ( not encrypted ) while
                     // using provided secret key & nonce, using Ascon-128
                     // algorithm
                     ascon::tag_t t = ascon::encrypt_128(k,
                                                         n,
                                                         a_data + ad_offset,
                                                         per_wi_ad_len,
                                                         text + ct_offset,
                                                         per_wi_ct_len,
                                                         cipher + ct_offset);

                     // write generated 128 -bit authentication tag to proper
                     // memory location
                     t.to_bytes(tag + knt_offset);
                   });
  });

  return evt;
}

// Given total `N` -bytes input plain text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous plain text byte slices ( each of
// length `L` -bytes ), this function will data-parallelly encrypt those `M`
// -many independent text slices, using Ascon-128a, while dispatching `M` -many
// SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For encrypting M -many equal length text slices, this function will also use
// M -many secret keys ( each 128 -bit ), nonces ( each 128 -bit ) & equal
// length associated data slices ( which are never encrypted but they're
// associated with respective plain text slice during encryption phase )
//
// After each work-item encrypts its portion of plain text, both ciphered text (
// length same as plain text ) & authentication tag ( 16 -bytes ) will be
// written to respective ( pre-allocated ) memory locations
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
static inline sycl::event
encrypt_128a(
  sycl::queue& q,
  const uint8_t* const __restrict sec_key, // input
  const size_t sec_key_len,                // bytes
  const uint8_t* const __restrict nonce,   // input
  const size_t nonce_len,                  // bytes
  const uint8_t* const __restrict a_data,  // input
  const size_t a_data_len,                 // bytes
  const uint8_t* const __restrict text,    // input
  const size_t text_len,                   // bytes
  uint8_t* const __restrict cipher,        // output
  const size_t cipher_len,                 // bytes
  uint8_t* const __restrict tag,           // output
  const size_t tag_len,                    // bytes
  const size_t wi_cnt,                     // SYCL work-item count
  const size_t wg_size,                    // SYCL work-group size
  const std::vector<sycl::event> evts      // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input plain text must be equally splitted among all work-items
  assert(text_len % wi_cnt == 0);
  // Total cipher text length must be equal to plain text length
  assert(text_len == cipher_len);
  // Each (work-item's) secret key is 16 -bytes ( 128 -bit )
  assert(sec_key_len == (wi_cnt << 4));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == sec_key_len);
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input plain text
  const size_t per_wi_ct_len = text_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(sycl::nd_range<1>{ wi_cnt, wg_size },
                   [=](sycl::nd_item<1> it) {
                     const size_t idx = it.get_global_linear_id();

                     // offset for secret key, nonce & authentication tag
                     const size_t knt_offset = idx << 4;
                     // offset for associated data ( byte array )
                     const size_t ad_offset = idx * per_wi_ad_len;
                     // offset for plain/ cipher text ( byte array )
                     const size_t ct_offset = idx * per_wi_ct_len;

                     // wrap secret key the way it's expected by encrypt routine
                     const ascon::secret_key_128_t k{ sec_key + knt_offset };
                     // wrap nonce the way it's expected by encrypt routine
                     const ascon::nonce_t n{ nonce + knt_offset };

                     // each work-item encrypts its portion of plain text (
                     // encrypted ) with associated data ( not encrypted ) while
                     // using provided secret key & nonce, using Ascon-128a
                     // algorithm
                     ascon::tag_t t = ascon::encrypt_128a(k,
                                                          n,
                                                          a_data + ad_offset,
                                                          per_wi_ad_len,
                                                          text + ct_offset,
                                                          per_wi_ct_len,
                                                          cipher + ct_offset);

                     // write generated 128 -bit authentication tag to proper
                     // memory location
                     t.to_bytes(tag + knt_offset);
                   });
  });

  return evt;
}

// Given total `N` -bytes input plain text, which is interpreted as `M` -many
// non-overlapping, independent, contiguous plain text byte slices ( each of
// length `L` -bytes ), this function will data-parallelly encrypt those `M`
// -many independent text slices, using Ascon-80pq, while dispatching `M` -many
// SYCL work-items, grouped by `K` -many work-items.
//
// So, N = M * L
//
// For encrypting M -many equal length text slices, this function will also use
// M -many secret keys ( each 160 -bit ), nonces ( each 128 -bit ) & equal
// length associated data slices ( which are never encrypted but they're
// associated with respective plain text slice during encryption phase )
//
// After each work-item encrypts its portion of plain text, both ciphered text (
// length same as plain text ) & authentication tag ( 16 -bytes ) will be
// written to respective ( pre-allocated ) memory offsets
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
static inline sycl::event
encrypt_80pq(
  sycl::queue& q,
  const uint8_t* const __restrict sec_key, // input
  const size_t sec_key_len,                // bytes
  const uint8_t* const __restrict nonce,   // input
  const size_t nonce_len,                  // bytes
  const uint8_t* const __restrict a_data,  // input
  const size_t a_data_len,                 // bytes
  const uint8_t* const __restrict text,    // input
  const size_t text_len,                   // bytes
  uint8_t* const __restrict cipher,        // output
  const size_t cipher_len,                 // bytes
  uint8_t* const __restrict tag,           // output
  const size_t tag_len,                    // bytes
  const size_t wi_cnt,                     // SYCL work-item count
  const size_t wg_size,                    // SYCL work-group size
  const std::vector<sycl::event> evts      // depends on completion of these
)
{
  // All work-group must have equal many work-items
  assert(wi_cnt % wg_size == 0);
  // Input associated data must be equally splitted among all work-items
  assert(a_data_len % wi_cnt == 0);
  // Input plain text must be equally splitted among all work-items
  assert(text_len % wi_cnt == 0);
  // Total cipher text length must be equal to plain text length
  assert(text_len == cipher_len);
  // Each (work-item's) secret key is 20 -bytes ( 160 -bit )
  assert(sec_key_len == (wi_cnt * 20));
  // Each (work-item's) public message nonce is 16 -bytes ( 128 -bit )
  assert(nonce_len == (wi_cnt << 4));
  // Each (work-item's) authentication tag is 16 -bytes ( 128 -bit )
  assert(nonce_len == tag_len);

  // each work-item will be required to consume 👇 -bytes input associated data
  const size_t per_wi_ad_len = a_data_len / wi_cnt;
  // each work-item will be required to consume 👇 -bytes input plain text
  const size_t per_wi_ct_len = text_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(sycl::nd_range<1>{ wi_cnt, wg_size },
                   [=](sycl::nd_item<1> it) {
                     const size_t idx = it.get_global_linear_id();

                     // offset for secret key
                     const size_t k_offset = idx * 20;
                     // offset for public message nonce & authentication tag
                     const size_t nt_offset = idx << 4;
                     // offset for associated data ( byte array )
                     const size_t ad_offset = idx * per_wi_ad_len;
                     // offset for plain/ cipher text ( byte array )
                     const size_t ct_offset = idx * per_wi_ct_len;

                     // wrap secret key the way it's expected by encrypt routine
                     const ascon::secret_key_160_t k{ sec_key + k_offset };

                     // wrap nonce the way it's expected by encrypt routine
                     const ascon::nonce_t n{ nonce + nt_offset };

                     // each work-item encrypts its portion of plain text (
                     // encrypted ) with associated data ( not encrypted ) while
                     // using provided secret key & nonce, using Ascon-80pq
                     // algorithm
                     ascon::tag_t t = ascon::encrypt_80pq(k,
                                                          n,
                                                          a_data + ad_offset,
                                                          per_wi_ad_len,
                                                          text + ct_offset,
                                                          per_wi_ct_len,
                                                          cipher + ct_offset);

                     // write generated 128 -bit authentication tag to proper
                     // memory location
                     t.to_bytes(tag + nt_offset);
                   });
  });

  return evt;
}

}
