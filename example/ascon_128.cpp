#include "aead/ascon128.hpp"
#include <cassert>
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include
// example/ascon_128.cpp
int
main()
{
  constexpr size_t ctlen = 64; // bytes
  constexpr size_t dlen = 32;  // bytes

  // acquire resources
  uint8_t* key = static_cast<uint8_t*>(malloc(ascon128_aead::KEY_LEN));
  uint8_t* nonce = static_cast<uint8_t*>(malloc(ascon128_aead::NONCE_LEN));
  uint8_t* tag = static_cast<uint8_t*>(malloc(ascon128_aead::TAG_LEN));
  uint8_t* data = static_cast<uint8_t*>(malloc(dlen));  // associated data
  uint8_t* text = static_cast<uint8_t*>(malloc(ctlen)); // plain text
  uint8_t* enc = static_cast<uint8_t*>(malloc(ctlen));  // ciphered text
  uint8_t* dec = static_cast<uint8_t*>(malloc(ctlen));  // deciphered text

  ascon_utils::random_data(key, ascon128_aead::KEY_LEN);
  ascon_utils::random_data(nonce, ascon128_aead::NONCE_LEN);
  ascon_utils::random_data(text, ctlen);
  ascon_utils::random_data(data, dlen);

  ascon128_aead::encrypt(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool f = ascon128_aead::decrypt(key, nonce, data, dlen, enc, ctlen, dec, tag);

  assert(f);

  std::cout << "Ascon-128 AEAD\n\n";
  std::cout << "Key       :\t" << ascon_utils::to_hex(key, 16) << "\n";
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
