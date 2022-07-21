#include "accel_ascon.hpp"

// Compile it with:
//
// dpcpp -std=c++20 -fsycl -O3 -I ./include example/accel_ascon_128.cpp
int
main()
{
  // set up SYCL device, context & kernel submission queue
  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  // these many instances of Ascon-128 to be invoked
  constexpr size_t wi_cnt = 1024ul;
  // these many Ascon-128 invocation instances to be grouped together
  constexpr size_t wg_size = 32ul;
  // each Ascon-128 invocation to encrypt 64 -bytes of input text
  constexpr size_t per_wi_ct_len = 64ul;
  // each Ascon-128 invocation to consume 32 -bytes of associated data
  // while authenticated encryption/ verified decryption
  //
  // note, associated data is never encrypted !
  constexpr size_t per_wi_ad_len = 32ul;
  // secret key, public message nonce & authentication tag ( generated after
  // authenticated encryption process ) --- each are of 128 -bits, to be used/
  // consumed by each work-item
  constexpr size_t per_wi_knt_len = sizeof(uint64_t) << 1;
  // each work-item to generate single boolean flag denoting status of Ascon-128
  // verified decryption
  constexpr size_t per_wi_flg_len = sizeof(bool);

  // total plain text/ encrypted/ decrypted bytes ( for all work-items )
  constexpr size_t ct_len = wi_cnt * per_wi_ct_len;
  // total associated data bytes ( for all work-items )
  constexpr size_t ad_len = wi_cnt * per_wi_ad_len;
  // total bytes for keeping secret key/ public message nonce/ authentication
  // tag ( for all work-items )
  constexpr size_t knt_len = wi_cnt * per_wi_knt_len;
  // bytes required for storing all verification flags computed by all
  // work-items
  constexpr size_t flg_len = wi_cnt * per_wi_flg_len;

  // plain text
  uint8_t* text = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // encrypted bytes
  uint8_t* enc = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // decrypted bytes
  uint8_t* dec = static_cast<uint8_t*>(sycl::malloc_shared(ct_len, q));
  // associated data bytes
  uint8_t* adb = static_cast<uint8_t*>(sycl::malloc_shared(ad_len, q));
  // secret keys
  uint8_t* keys = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // public message nonces
  uint8_t* nonces = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // authentication tags
  uint8_t* tags = static_cast<uint8_t*>(sycl::malloc_shared(knt_len, q));
  // verification flags
  bool* flags = static_cast<bool*>(sycl::malloc_shared(flg_len, q));

  // prepare random plain text bytes
  ascon_utils::random_data(text, ct_len);
  // prepare random associated data bytes
  ascon_utils::random_data(adb, ad_len);
  // prepare random secret keys
  ascon_utils::random_data(keys, knt_len);
  // prepare random public message nonces
  ascon_utils::random_data(nonces, knt_len);

  using evt = sycl::event;

  evt e0 = q.memset(enc, 0, ct_len);
  evt e1 = q.memset(tags, 0, knt_len);

  // generate encrypted bytes & authentication tags
  evt e2 = accel_ascon::encrypt_128(q,
                                    keys,
                                    knt_len,
                                    nonces,
                                    knt_len,
                                    adb,
                                    ad_len,
                                    text,
                                    ct_len,
                                    enc,
                                    ct_len,
                                    tags,
                                    knt_len,
                                    wi_cnt,
                                    wg_size,
                                    { e0, e1 });

  evt e3 = q.memset(dec, 0, ct_len);
  evt e4 = q.memset(flags, 0, flg_len);

  // generate decrypted bytes & verification flags
  evt e5 = accel_ascon::decrypt_128(q,
                                    keys,
                                    knt_len,
                                    nonces,
                                    knt_len,
                                    adb,
                                    ad_len,
                                    enc,
                                    ct_len,
                                    tags,
                                    knt_len,
                                    dec,
                                    ct_len,
                                    flags,
                                    flg_len,
                                    wi_cnt,
                                    wg_size,
                                    { e2, e3, e4 });

  // host synchronization
  e5.wait();

  // check that verification flag is true for all Ascon-128 instances ( check it
  // sequentially on host )
  for (size_t wi = 0; wi < wi_cnt; wi++) {
    assert(flags[wi]);

    // do a byte-by-byte comparison to be sure that each decrypted byte
    // matches each original plain text byte
    const size_t ct_off = wi * per_wi_ct_len;
    for (size_t b = 0; b < per_wi_ct_len; b++) {
      assert(text[ct_off + b] == dec[ct_off + b]);
    }
  }

  std::cout << "Accelerated Ascon-128 works !" << std::endl;

  // deallocate all acquired memory resources
  sycl::free(text, q);
  sycl::free(enc, q);
  sycl::free(dec, q);
  sycl::free(adb, q);
  sycl::free(keys, q);
  sycl::free(nonces, q);
  sycl::free(tags, q);
  sycl::free(flags, q);

  return EXIT_SUCCESS;
}
