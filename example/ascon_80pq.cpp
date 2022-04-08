#include "ascon.hpp"
#include <cassert>
#include <iostream>

// Compile & execute with
//
// `g++ -std=c++20 -I ./include example/ascon_80pq.cpp && ./a.out`
int
main()
{
  constexpr const size_t text_len = 64;      // bytes
  constexpr const size_t data_len = 32;      // bytes
  constexpr const size_t enc_len = text_len; // bytes
  constexpr const size_t dec_len = enc_len;  // bytes

  // acquire resources
  uint8_t* text = static_cast<uint8_t*>(malloc(text_len)); // plain text
  uint8_t* data = static_cast<uint8_t*>(malloc(data_len)); // associated data
  uint8_t* enc = static_cast<uint8_t*>(malloc(enc_len));   // ciphered data
  uint8_t* dec = static_cast<uint8_t*>(malloc(dec_len));   // deciphered data

  // prepare 160 -bit secret key
  ascon::secret_key_160_t k = { { 1ul, 2ul, 3ul } };
  // prepare 128 -bit message nonce, don't repeat nonce for same secret key !
  ascon::nonce_t n = { { 4ul, 5ul } };

// prepare associated data, it's never encrypted !
#if defined __clang__
#pragma unroll 8
#endif
  for (size_t i = 0; i < data_len; i++) {
    data[i] = static_cast<uint8_t>(i);
  }

  // prepare plain text, it'll be encrypted !
#if defined __clang__
#pragma unroll 8
#endif
  for (size_t i = 0; i < text_len; i++) {
    text[i] = static_cast<uint8_t>(i);
  }

  // using Ascon-80pq for running encrypt -> decrypt cycle
  using namespace ascon;
  const tag_t t = encrypt_80pq(k, n, data, data_len, text, text_len, enc);
  const bool f = decrypt_80pq(k, n, data, data_len, enc, enc_len, dec, t);

  // verified decryption; it must be true !
  assert(f);

  const std::string text_ = ascon_utils::tohex(text, text_len);
  const std::string enc_ = ascon_utils::tohex(enc, enc_len);
  const std::string dec_ = ascon_utils::tohex(dec, dec_len);

  // redundant check; if `f` is true, `dec` is good to consume !
  assert(text_ == dec_);

  std::cout << "Ascon-80pq AEAD" << std::endl << std::endl;
  std::cout << "Plain      text :\t" << text_ << std::endl;
  std::cout << "Cipher     text :\t" << enc_ << std::endl;
  std::cout << "Deciphered text :\t" << dec_ << std::endl;

  // deallocate resources
  free(text);
  free(data);
  free(enc);
  free(dec);

  return EXIT_SUCCESS;
}
