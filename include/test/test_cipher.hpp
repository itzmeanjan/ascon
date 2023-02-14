#pragma once
#include "auth_enc.hpp"
#include "verf_dec.hpp"
#include <cassert>
#include <string.h>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Test correctness of Ascon-128 authenticated encryption and verified
// decryption implementation for different input sizes
void
ascon_128(const size_t dlen, // bytes; >= 0
          const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(16));
  auto nonce = static_cast<uint8_t*>(std::malloc(16));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));
  auto tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dlen);
  ascon_utils::random_data(text, ctlen);

  ascon::encrypt_128(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool v = ascon::decrypt_128(key, nonce, data, dlen, enc, ctlen, dec, tag);

  // ensures that text has been verifiably decrypted !
  assert(v);
  for (size_t i = 0; i < ctlen; i++) {
    assert(text[i] == dec[i]);
  }

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
  std::free(tag);
}

// Test correctness of Ascon-128a authenticated encryption and verified
// decryption implementation for different input sizes
void
ascon_128a(const size_t dlen, // bytes; >= 0
           const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(16));
  auto nonce = static_cast<uint8_t*>(std::malloc(16));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));
  auto tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dlen);
  ascon_utils::random_data(text, ctlen);

  ascon::encrypt_128a(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool v = ascon::decrypt_128a(key, nonce, data, dlen, enc, ctlen, dec, tag);

  // ensures that text has been verifiably decrypted !
  assert(v);
  for (size_t i = 0; i < ctlen; i++) {
    assert(text[i] == dec[i]);
  }

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
  std::free(tag);
}

// Test correctness of Ascon-80pq authenticated encryption and verified
// decryption implementation
void
ascon_80pq(const size_t d_len /* bytes */, const size_t t_len /* bytes */)
{
  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * d_len));
  ascon_utils::random_data(data, d_len);

  uint8_t* text = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * t_len));
  ascon_utils::random_data(text, t_len);

  const size_t enc_len = t_len; // bytes
  uint8_t* enc = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * enc_len));
  memset(enc, 0, enc_len);

  const size_t dec_len = enc_len; // bytes
  uint8_t* dec = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * dec_len));
  memset(dec, 0, dec_len);

  // 128 -bit tag
  using tag_t = ascon::tag_t;

  const tag_t t = ascon::encrypt_80pq(k, n, data, d_len, text, t_len, enc);
  const bool v = ascon::decrypt_80pq(k, n, data, d_len, enc, t_len, dec, t);

  // ensures that text has been decrypted & verified !
  assert(v);

  // byte-by-byte check to be sure that `encrypt -> decrypt` process behaved as
  // expected !
  for (size_t i = 0; i < t_len; i++) {
    assert(text[i] == dec[i]);
  }

  // deallocate memory
  free(data);
  free(text);
  free(enc);
  free(dec);
}

}
