#include "aead.hpp"
#include <cassert>
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include example/ascon_80pq.cpp
int
main()
{
  constexpr size_t ctlen = 64; // bytes
  constexpr size_t dlen = 32;  // bytes

  // acquire resources
  uint8_t* key = static_cast<uint8_t*>(malloc(ascon::ASCON80PQ_KEY_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(ascon::ASCON80PQ_NONCE_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(ascon::ASCON80PQ_TAG_LEN));
  uint8_t* data = static_cast<uint8_t*>(malloc(dlen));  // associated data
  uint8_t* text = static_cast<uint8_t*>(malloc(ctlen)); // plain text
  uint8_t* enc = static_cast<uint8_t*>(malloc(ctlen));  // ciphered text
  uint8_t* dec = static_cast<uint8_t*>(malloc(ctlen));  // deciphered text

  ascon_utils::random_data(key, ascon::ASCON80PQ_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON80PQ_NONCE_LEN);
  ascon_utils::random_data(text, ctlen);
  ascon_utils::random_data(data, dlen);

  ascon::encrypt_80pq(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool f = ascon::decrypt_80pq(key, nonce, data, dlen, enc, ctlen, dec, tag);

  assert(f);

  std::cout << "Ascon-80pq AEAD\n\n";
  std::cout << "Key       :\t" << ascon_utils::to_hex(key, 20) << "\n";
  std::cout << "Nonce     :\t" << ascon_utils::to_hex(nonce, 16) << "\n";
  std::cout << "Data      :\t" << ascon_utils::to_hex(data, dlen) << "\n";
  std::cout << "Text      :\t" << ascon_utils::to_hex(text, ctlen) << "\n";
  std::cout << "Encrypted :\t" << ascon_utils::to_hex(enc, ctlen) << "\n";
  std::cout << "Decrypted :\t" << ascon_utils::to_hex(dec, ctlen) << "\n";

  // deallocate resources
  free(key);
  free(nonce);
  free(tag);
  free(data);
  free(text);
  free(enc);
  free(dec);

  return EXIT_SUCCESS;
}
