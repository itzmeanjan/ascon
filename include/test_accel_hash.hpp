#pragma once
#include "accel_hash.hpp"
#include <cassert>

// Test SYCL accelerated data parallel implementation of Ascon cryptographic
// suite
namespace accel_ascon_test {

static void
hash(sycl::queue& q,
     const size_t per_wi_msg_len, // bytes
     const size_t wi_cnt,         // wi_cnt % wg_size == 0
     const size_t wg_size)
{
  // type aliasing
  using evt = sycl::event;
  using evts = std::vector<evt>;

  // total input message length ( in bytes )
  const size_t m_len = per_wi_msg_len * wi_cnt;
  // total output digest length ( in bytes );
  // remember Ascon-Hash produces 32 -bytes digest
  const size_t d_len = wi_cnt << 5;

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(sycl::malloc_shared(m_len, q));
  uint8_t* dig0 = static_cast<uint8_t*>(sycl::malloc_shared(d_len, q));
  uint8_t* dig1 = static_cast<uint8_t*>(sycl::malloc_shared(d_len, q));

  // generate random input on host
  ascon_utils::random_data(msg, m_len);

  // clear memory for keeping output digests
  evt e0 = q.memset(dig0, 0, d_len);
  evt e1 = q.memset(dig1, 0, d_len);

  // compute `wi_cnt` many Ascon-Hash digests parallelly !
  evts e2{ e0, e1 };
  evt e3 = accel_ascon::hash(q, msg, m_len, dig0, d_len, wi_cnt, wg_size, e2);
  e3.wait();

  // sequentially compute all `wi_cnt` -many Ascon-Hash digests for byte-by-byte
  // assertion !
  for (size_t i = 0; i < wi_cnt; i++) {
    ascon::hash(msg + i * per_wi_msg_len, per_wi_msg_len, dig1 + (i << 5));

    for (size_t j = 0; j < 32; j++) {
      assert(dig0[(i << 5) + j] == dig1[(i << 5) + j]);
    }
  }

  // release resources
  sycl::free(msg, q);
  sycl::free(dig0, q);
  sycl::free(dig1, q);
}

static void
hash_a(sycl::queue& q,
       const size_t per_wi_msg_len, // bytes
       const size_t wi_cnt,         // wi_cnt % wg_size == 0
       const size_t wg_size)
{
  // type aliasing
  using evt = sycl::event;
  using evts = std::vector<evt>;

  // total input message length ( in bytes )
  const size_t m_len = per_wi_msg_len * wi_cnt;
  // total output digest length ( in bytes );
  // remember Ascon-HashA produces 32 -bytes digest
  const size_t d_len = wi_cnt << 5;

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(sycl::malloc_shared(m_len, q));
  uint8_t* dig0 = static_cast<uint8_t*>(sycl::malloc_shared(d_len, q));
  uint8_t* dig1 = static_cast<uint8_t*>(sycl::malloc_shared(d_len, q));

  // generate random input on host
  ascon_utils::random_data(msg, m_len);

  // clear memory for keeping output digests
  evt e0 = q.memset(dig0, 0, d_len);
  evt e1 = q.memset(dig1, 0, d_len);

  // compute `wi_cnt` many Ascon-HashA digests parallelly !
  evts e2{ e0, e1 };
  evt e3 = accel_ascon::hash_a(q, msg, m_len, dig0, d_len, wi_cnt, wg_size, e2);
  e3.wait();

  // sequentially compute all `wi_cnt` -many Ascon-HashA digests for
  // byte-by-byte assertion !
  for (size_t i = 0; i < wi_cnt; i++) {
    ascon::hash_a(msg + i * per_wi_msg_len, per_wi_msg_len, dig1 + (i << 5));

    for (size_t j = 0; j < 32; j++) {
      assert(dig0[(i << 5) + j] == dig1[(i << 5) + j]);
    }
  }

  // release resources
  sycl::free(msg, q);
  sycl::free(dig0, q);
  sycl::free(dig1, q);
}

}
