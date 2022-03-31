#pragma once
#include "hash.hpp"
#include <CL/sycl.hpp>

// SYCL accelerated Ascon Light Weight Cryptography ( i.e. authenticated
// encryption, verified decryption and hashing ) Implementation
namespace accel_ascon {

// Given (total) `N` -bytes input message, which can be interpreted as `M` -many
// non-overlapping, independent message byte slices ( each of length `L` -bytes
// ), this function will dispatch `M` -many SYCL work-items ( with work-group
// size of `K` ), who will parallelly compute Ascon-Hash digests ( each 32
// -bytes ) for M -many independent ( equal length ) message slices.
//
// In following setup,
//
//    N = msg_len
//    M = wi_cnt
//    L = per_wi_msg_len
//    K = wg_size
//
// Input message slices should be contiguously placed in `msg`
// Similarly output digests shall be contiguously placed in `digest`, must
// allocate `32 * wi_cnt` -bytes memory !
static inline sycl::event
hash(sycl::queue& q,
     const uint8_t* const __restrict msg, // input
     const size_t msg_len,                // bytes
     uint8_t* const __restrict digest,    // output
     const size_t digest_len,             // bytes
     const size_t wi_cnt,                 // SYCL work-item count
     const size_t wg_size,                // SYCL work-group size
     const std::vector<sycl::event> evts  // depends on these events
)
{
  // All work groups must have same number of active work-items
  assert(wi_cnt % wg_size == 0);
  // Ascon-Hash digest length is 256 -bit ( 32 -bytes )
  assert(digest_len == (wi_cnt << 5));
  // Input message can be equally splitted among all dispatched work-items,
  // so that `wi_cnt` -many independent Ascon-Hash(-es) can be computed
  // parallelly
  assert(msg_len % wi_cnt == 0);

  // each work-item will be required to consume 👇 -bytes input message
  const size_t per_wi_msg_len = msg_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        const size_t m_offset = idx * per_wi_msg_len; // bytes
        const size_t d_offset = idx << 5;             // bytes

        ascon::hash(msg + m_offset, per_wi_msg_len, digest + d_offset);
      });
  });

  return evt;
}

// Given (total) `N` -bytes input message, which can be interpreted as `M` -many
// non-overlapping, independent message byte slices ( each of length `L` -bytes
// ), this function will dispatch `M` -many SYCL work-items ( with work-group
// size of `K` ), who will parallelly compute Ascon-HashA digests ( each 32
// -bytes ) for M -many independent ( equal length ) message slices.
//
// In following setup,
//
//    N = msg_len
//    M = wi_cnt
//    L = per_wi_msg_len
//    K = wg_size
//
// Input message slices should be contiguously placed in `msg`
// Similarly output digests shall be contiguously placed in `digest`, must
// allocate `32 * wi_cnt` -bytes memory !
static inline sycl::event
hash_a(sycl::queue& q,
       const uint8_t* const __restrict msg, // input
       const size_t msg_len,                // bytes
       uint8_t* const __restrict digest,    // output
       const size_t digest_len,             // bytes
       const size_t wi_cnt,                 // SYCL work-item count
       const size_t wg_size,                // SYCL work-group size
       const std::vector<sycl::event> evts  // depends on these events
)
{
  // All work groups must have same number of active work-items
  assert(wi_cnt % wg_size == 0);
  // Ascon-HashA digest length is 256 -bit ( 32 -bytes )
  assert(digest_len == (wi_cnt << 5));
  // Input message can be equally splitted among all dispatched work-items,
  // so that `wi_cnt` -many independent Ascon-HashA(-es) can be computed
  // parallelly
  assert(msg_len % wi_cnt == 0);

  // each work-item will be required to consume 👇 -bytes input message
  const size_t per_wi_msg_len = msg_len / wi_cnt;

  sycl::event evt = q.submit([&](sycl::handler& h) {
    h.depends_on(evts);
    h.parallel_for(
      sycl::nd_range<1>{ wi_cnt, wg_size }, [=](sycl::nd_item<1> it) {
        const size_t idx = it.get_global_linear_id();

        const size_t m_offset = idx * per_wi_msg_len; // bytes
        const size_t d_offset = idx << 5;             // bytes

        ascon::hash_a(msg + m_offset, per_wi_msg_len, digest + d_offset);
      });
  });

  return evt;
}

}
