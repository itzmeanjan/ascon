#include "aead/ascon80pq.hpp"
#include <cassert>
#include <iostream>

// Compile with
//
// g++ -std=c++20 -Wall -O3 -march=native -I ./include -I ./subtle/include examples/ascon80pq_aead.cpp
int
main()
{
  constexpr size_t ctlen = 64; // bytes
  constexpr size_t dlen = 32;  // bytes

  std::vector<uint8_t> key(ascon80pq_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon80pq_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon80pq_aead::TAG_LEN);
  std::vector<uint8_t> data(dlen);
  std::vector<uint8_t> text(ctlen);
  std::vector<uint8_t> enc(ctlen);
  std::vector<uint8_t> dec(ctlen);

  auto _key = std::span<uint8_t, ascon80pq_aead::KEY_LEN>(key);
  auto _nonce = std::span<uint8_t, ascon80pq_aead::NONCE_LEN>(nonce);
  auto _tag = std::span<uint8_t, ascon80pq_aead::TAG_LEN>(tag);
  auto _data = std::span(data);
  auto _text = std::span(text);
  auto _enc = std::span(enc);
  auto _dec = std::span(dec);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data<uint8_t>(_nonce);
  ascon_utils::random_data(_text);
  ascon_utils::random_data(_data);

  ascon80pq_aead::encrypt(_key, _nonce, _data, _text, _enc, _tag);
  bool f = ascon80pq_aead::decrypt(_key, _nonce, _data, _enc, _dec, _tag);

  assert(f);
  assert(std::ranges::equal(_text, _dec));

  std::cout << "Ascon-80pq AEAD\n\n";
  std::cout << "Key       :\t" << ascon_utils::to_hex(_key) << "\n";
  std::cout << "Nonce     :\t" << ascon_utils::to_hex(_nonce) << "\n";
  std::cout << "Data      :\t" << ascon_utils::to_hex(_data) << "\n";
  std::cout << "Text      :\t" << ascon_utils::to_hex(_text) << "\n";
  std::cout << "Encrypted :\t" << ascon_utils::to_hex(_enc) << "\n";
  std::cout << "Decrypted :\t" << ascon_utils::to_hex(_dec) << "\n";

  return EXIT_SUCCESS;
}
