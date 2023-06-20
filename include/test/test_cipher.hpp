#pragma once
#include "aead.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Test correctness of Ascon-128a authenticated encryption and verified
// decryption implementation for different input sizes
inline void
ascon_128a(const size_t dlen, // bytes; >= 0
           const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));

  ascon_utils::random_data(key, ascon::ASCON128A_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128A_NONCE_LEN);
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
inline void
ascon_80pq(const size_t dlen, // bytes; >= 0
           const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));

  ascon_utils::random_data(key, ascon::ASCON80PQ_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON80PQ_NONCE_LEN);
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
