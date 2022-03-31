#pragma once
#include "auth_enc.hpp"
#include "verf_dec.hpp"
#include <cassert>
#include <string.h>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Test correctness of Ascon-128 authenticated encryption and verified
// decryption implementation
static void
ascon_128(const size_t data_len /* bytes */, const size_t text_len /* bytes */)
{
  ascon::secret_key_t k;
  ascon_utils::random_data(k.limbs, 2);

  ascon::nonce_t n;
  ascon_utils::random_data(n.limbs, 2);

  uint8_t* data = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * data_len));
  ascon_utils::random_data(data, data_len);

  uint8_t* text = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * text_len));
  ascon_utils::random_data(text, text_len);

  const size_t enc_len = text_len; // bytes
  uint8_t* enc = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * enc_len));
  memset(enc, 0, enc_len);

  const size_t dec_len = enc_len; // bytes
  uint8_t* dec = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * dec_len));
  memset(dec, 0, dec_len);

  // 128 -bit tag
  using tag_t = ascon::tag_t;

  const tag_t t = ascon::encrypt_128(k, n, data, data_len, text, text_len, enc);
  const bool v = ascon::decrypt_128(k, n, data, data_len, enc, enc_len, dec, t);

  // ensures that text has been decrypted & verified !
  assert(v);

  // byte-by-byte check to be sure that `encrypt -> decrypt` process behaved as
  // expected !
  for (size_t i = 0; i < text_len; i++) {
    assert(text[i] == dec[i]);
  }

  // deallocate memory
  free(data);
  free(text);
  free(enc);
  free(dec);
}

// Test correctness of Ascon-128a authenticated encryption and verified
// decryption implementation
static void
ascon_128a(const size_t data_len /* bytes */, const size_t text_len /* bytes */)
{
  ascon::secret_key_t k;
  ascon_utils::random_data(k.limbs, 2);

  ascon::nonce_t n;
  ascon_utils::random_data(n.limbs, 2);

  uint8_t* data = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * data_len));
  ascon_utils::random_data(data, data_len);

  uint8_t* text = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * text_len));
  ascon_utils::random_data(text, text_len);

  const size_t enc_len = text_len; // bytes
  uint8_t* enc = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * enc_len));
  memset(enc, 0, enc_len);

  const size_t dec_len = enc_len; // bytes
  uint8_t* dec = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * dec_len));
  memset(dec, 0, dec_len);

  {
    using namespace ascon;

    const tag_t t = encrypt_128a(k, n, data, data_len, text, text_len, enc);
    const bool v = decrypt_128a(k, n, data, data_len, enc, enc_len, dec, t);

    // ensures that text has been decrypted & verified !
    assert(v);
  }

  // byte-by-byte check to be sure that `encrypt -> decrypt` process behaved as
  // expected !
  for (size_t i = 0; i < text_len; i++) {
    assert(text[i] == dec[i]);
  }

  // deallocate memory
  free(data);
  free(text);
  free(enc);
  free(dec);
}

}
