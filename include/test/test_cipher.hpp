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
ascon_80pq(const size_t dlen, // bytes; >= 0
           const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(20));
  auto nonce = static_cast<uint8_t*>(std::malloc(16));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));
  auto tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 20);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dlen);
  ascon_utils::random_data(text, ctlen);

  ascon::encrypt_80pq(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool v = ascon::decrypt_80pq(key, nonce, data, dlen, enc, ctlen, dec, tag);

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

}
