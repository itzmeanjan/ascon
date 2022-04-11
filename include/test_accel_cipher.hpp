#pragma once
#include "accel_auth_enc.hpp"
#include "accel_verf_dec.hpp"
#include <cassert>

// Test SYCL accelerated data parallel implementation of Ascon cryptographic
// suite
namespace accel_ascon_test {

static void
ascon_128(sycl::queue& q,
          const size_t per_wi_ad_len, // bytes
          const size_t per_wi_ct_len, // bytes
          const size_t wi_cnt,
          const size_t wg_size)
{
  // type aliasing
  using evt = sycl::event;

  const size_t ct_len = per_wi_ct_len * wi_cnt;            // bytes
  const size_t ad_len = per_wi_ad_len * wi_cnt;            // bytes
  const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt; // bytes
  const size_t flag_len = sizeof(bool) * wi_cnt;           // bytes

  // plain text
  uint8_t* txt = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // encrypted bytes
  uint8_t* enc = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // decrypted bytes
  uint8_t* dec = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // associated data bytes
  uint8_t* ad = static_cast<uint8_t*>(sycl::malloc_shared(ad_len, q));
  // secret keys ( each 128 -bit )
  uint8_t* key = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // public message nonces ( each 128 -bit )
  uint8_t* nonce = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // authentication tags ( each 128 -bit )
  uint8_t* tag = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // verification flags ( boolean )
  bool* flag = static_cast<bool*>(sycl::malloc_shared(flag_len, q));

  ascon_utils::random_data(txt, ct_len);
  ascon_utils::random_data(ad, ad_len);
  ascon_utils::random_data(key, knt_len);
  ascon_utils::random_data(nonce, knt_len);

  evt e0 = q.memset(enc, 0, ct_len);
  evt e1 = q.memset(tag, 0, knt_len);
  evt e2 = q.memset(flag, 0, flag_len);

  // first encrypt N -many independent plain text slice using Ascon-128
  evt e3 = accel_ascon::encrypt_128(q,
                                    key,
                                    knt_len,
                                    nonce,
                                    knt_len,
                                    ad,
                                    ad_len,
                                    txt,
                                    ct_len,
                                    enc,
                                    ct_len,
                                    tag,
                                    knt_len,
                                    wi_cnt,
                                    wg_size,
                                    { e0, e1 });

  // then decrypt N -many independent cipher text slice using Ascon-128
  evt e4 = accel_ascon::decrypt_128(q,
                                    key,
                                    knt_len,
                                    nonce,
                                    knt_len,
                                    ad,
                                    ad_len,
                                    enc,
                                    ct_len,
                                    tag,
                                    knt_len,
                                    dec,
                                    ct_len,
                                    flag,
                                    flag_len,
                                    wi_cnt,
                                    wg_size,
                                    { e2, e3 });

  e4.wait();

  // ensure verified decryption happened as expected !
  for (size_t i = 0; i < wi_cnt; i++) {
    assert(flag[i]);
  }

  // release all resources
  sycl::free(txt, q);
  sycl::free(enc, q);
  sycl::free(dec, q);
  sycl::free(ad, q);
  sycl::free(key, q);
  sycl::free(nonce, q);
  sycl::free(tag, q);
  sycl::free(flag, q);
}

static void
ascon_128a(sycl::queue& q,
           const size_t per_wi_ad_len, // bytes
           const size_t per_wi_ct_len, // bytes
           const size_t wi_cnt,
           const size_t wg_size)
{
  // type aliasing
  using evt = sycl::event;

  const size_t ct_len = per_wi_ct_len * wi_cnt;            // bytes
  const size_t ad_len = per_wi_ad_len * wi_cnt;            // bytes
  const size_t knt_len = (sizeof(uint64_t) << 1) * wi_cnt; // bytes
  const size_t flag_len = sizeof(bool) * wi_cnt;           // bytes

  // plain text
  uint8_t* txt = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // encrypted bytes
  uint8_t* enc = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // decrypted bytes
  uint8_t* dec = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // associated data bytes
  uint8_t* ad = static_cast<uint8_t*>(sycl::malloc_shared(ad_len, q));
  // secret keys ( each 128 -bit )
  uint8_t* key = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // public message nonces ( each 128 -bit )
  uint8_t* nonce = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // authentication tags ( each 128 -bit )
  uint8_t* tag = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // verification flags ( boolean )
  bool* flag = static_cast<bool*>(sycl::malloc_shared(flag_len, q));

  ascon_utils::random_data(txt, ct_len);
  ascon_utils::random_data(ad, ad_len);
  ascon_utils::random_data(key, knt_len);
  ascon_utils::random_data(nonce, knt_len);

  evt e0 = q.memset(enc, 0, ct_len);
  evt e1 = q.memset(tag, 0, knt_len);
  evt e2 = q.memset(dec, 0, ct_len);
  evt e3 = q.memset(flag, 0, flag_len);

  // first encrypt N -many independent plain text slice using Ascon-128a
  evt e4 = accel_ascon::encrypt_128a(q,
                                     key,
                                     knt_len,
                                     nonce,
                                     knt_len,
                                     ad,
                                     ad_len,
                                     txt,
                                     ct_len,
                                     enc,
                                     ct_len,
                                     tag,
                                     knt_len,
                                     wi_cnt,
                                     wg_size,
                                     { e0, e1 });

  // then decrypt N -many independent cipher text slice using Ascon-128a
  evt e5 = accel_ascon::decrypt_128a(q,
                                     key,
                                     knt_len,
                                     nonce,
                                     knt_len,
                                     ad,
                                     ad_len,
                                     enc,
                                     ct_len,
                                     tag,
                                     knt_len,
                                     dec,
                                     ct_len,
                                     flag,
                                     flag_len,
                                     wi_cnt,
                                     wg_size,
                                     { e2, e3, e4 });

  e5.wait();

  // ensure verified decryption happened as expected !
  for (size_t i = 0; i < wi_cnt; i++) {
    assert(flag[i]);

    // do a byte-by-byte comparison between original plain text & deciphered
    // text
    const size_t ct_offset = i * per_wi_ct_len;
    for (size_t j = 0; j < per_wi_ct_len; j++) {
      assert(txt[ct_offset + j] == dec[ct_offset + j]);
    }
  }

  // release all resources
  sycl::free(txt, q);
  sycl::free(enc, q);
  sycl::free(dec, q);
  sycl::free(ad, q);
  sycl::free(key, q);
  sycl::free(nonce, q);
  sycl::free(tag, q);
  sycl::free(flag, q);
}

static void
ascon_80pq(sycl::queue& q,
           const size_t per_wi_ad_len, // bytes
           const size_t per_wi_ct_len, // bytes
           const size_t wi_cnt,
           const size_t wg_size)
{
  // type aliasing
  using evt = sycl::event;

  const size_t ct_len = per_wi_ct_len * wi_cnt;           // bytes
  const size_t ad_len = per_wi_ad_len * wi_cnt;           // bytes
  const size_t k_len = 20ul * wi_cnt;                     // bytes
  const size_t nt_len = (sizeof(uint64_t) << 1) * wi_cnt; // bytes
  const size_t flag_len = sizeof(bool) * wi_cnt;          // bytes

  // plain text
  uint8_t* txt = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // encrypted bytes
  uint8_t* enc = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // decrypted bytes
  uint8_t* dec = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // associated data bytes
  uint8_t* ad = static_cast<uint8_t*>(sycl::malloc_shared(ad_len, q));
  // secret keys ( each 160 -bit )
  uint8_t* key = static_cast<uint8_t*>(sycl::malloc_shared(k_len, q));
  // public message nonces ( each 128 -bit )
  uint8_t* nonce = static_cast<uint8_t*>(sycl::malloc_shared(nt_len, q));
  // authentication tags ( each 128 -bit )
  uint8_t* tag = static_cast<uint8_t*>(sycl::malloc_shared(nt_len, q));
  // verification flags ( boolean )
  bool* flag = static_cast<bool*>(sycl::malloc_shared(flag_len, q));

  ascon_utils::random_data(txt, ct_len);
  ascon_utils::random_data(ad, ad_len);
  ascon_utils::random_data(key, k_len);
  ascon_utils::random_data(nonce, nt_len);

  evt e0 = q.memset(enc, 0, ct_len);
  evt e1 = q.memset(tag, 0, nt_len);
  evt e2 = q.memset(flag, 0, flag_len);

  // first encrypt N -many independent plain text slice using Ascon-80pq
  evt e3 = accel_ascon::encrypt_80pq(q,
                                     key,
                                     k_len,
                                     nonce,
                                     nt_len,
                                     ad,
                                     ad_len,
                                     txt,
                                     ct_len,
                                     enc,
                                     ct_len,
                                     tag,
                                     nt_len,
                                     wi_cnt,
                                     wg_size,
                                     { e0, e1 });

  // then decrypt N -many independent cipher text slice using Ascon-80pq
  evt e4 = accel_ascon::decrypt_80pq(q,
                                     key,
                                     k_len,
                                     nonce,
                                     nt_len,
                                     ad,
                                     ad_len,
                                     enc,
                                     ct_len,
                                     tag,
                                     nt_len,
                                     dec,
                                     ct_len,
                                     flag,
                                     flag_len,
                                     wi_cnt,
                                     wg_size,
                                     { e2, e3 });

  e4.wait();

  // ensure verified decryption happened as expected !
  for (size_t i = 0; i < wi_cnt; i++) {
    assert(flag[i]);
  }

  // release all resources
  sycl::free(txt, q);
  sycl::free(enc, q);
  sycl::free(dec, q);
  sycl::free(ad, q);
  sycl::free(key, q);
  sycl::free(nonce, q);
  sycl::free(tag, q);
  sycl::free(flag, q);
}

}
