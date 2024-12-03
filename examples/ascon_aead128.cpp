#include "ascon/aead/ascon_aead128.hpp"
#include "example_helper.hpp"
#include <array>
#include <cassert>
#include <iostream>

int
main()
{
  constexpr size_t plaintext_byte_len = 64;
  constexpr size_t associated_data_byte_len = 32;

  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};
  std::vector<uint8_t> associated_data(associated_data_byte_len);
  std::vector<uint8_t> plain_text(plaintext_byte_len);
  std::vector<uint8_t> cipher_text(plaintext_byte_len);
  std::vector<uint8_t> deciphered_text(plaintext_byte_len);

  generate_random_data<uint8_t>(key);
  generate_random_data<uint8_t>(nonce);
  generate_random_data<uint8_t>(associated_data);
  generate_random_data<uint8_t>(plain_text);

  ascon_aead128::encrypt(key, nonce, associated_data, plain_text, cipher_text, tag);
  const bool is_decrypted = ascon_aead128::decrypt(key, nonce, associated_data, cipher_text, deciphered_text, tag);

  assert(is_decrypted);
  assert(std::ranges::equal(plain_text, deciphered_text));

  std::cout << "Ascon-AEAD128\n\n";
  std::cout << "Key       :\t" << bytes_to_hex_string(key) << "\n";
  std::cout << "Nonce     :\t" << bytes_to_hex_string(nonce) << "\n";
  std::cout << "Data      :\t" << bytes_to_hex_string(associated_data) << "\n";
  std::cout << "Text      :\t" << bytes_to_hex_string(plain_text) << "\n";
  std::cout << "Encrypted :\t" << bytes_to_hex_string(cipher_text) << "\n";
  std::cout << "Decrypted :\t" << bytes_to_hex_string(deciphered_text) << "\n";

  return EXIT_SUCCESS;
}
