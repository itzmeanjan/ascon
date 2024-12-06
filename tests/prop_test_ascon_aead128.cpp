#include "ascon/aead/ascon_aead128.hpp"
#include "test_helper.hpp"
#include <array>
#include <cassert>
#include <gtest/gtest.h>

constexpr std::array<char, 2 * ascon_aead128::TAG_BYTE_LEN>
eval_encrypt_decrypt()
{
  constexpr size_t ASSOCIATED_DATA_BYTE_LEN = 32;
  constexpr size_t PLAIN_TEXT_BYTE_LEN = 32;

  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key;
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce;
  std::array<uint8_t, ASSOCIATED_DATA_BYTE_LEN> associated_data;
  std::array<uint8_t, PLAIN_TEXT_BYTE_LEN> plain_text;

  std::iota(key.begin(), key.end(), 0);
  std::iota(nonce.begin(), nonce.end(), 0);
  std::iota(associated_data.begin(), associated_data.end(), 0);
  std::iota(plain_text.begin(), plain_text.end(), 0);

  std::array<uint8_t, PLAIN_TEXT_BYTE_LEN> cipher_text;
  std::array<uint8_t, PLAIN_TEXT_BYTE_LEN> deciphered_text;
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag;

  ascon_aead128::encrypt(key, nonce, associated_data, plain_text, cipher_text, tag);
  const bool is_decrypted = ascon_aead128::decrypt(key, nonce, associated_data, cipher_text, deciphered_text, tag);

  assert(is_decrypted);
  return bytes_to_hex(tag);
}

TEST(AsconAEAD128, CompileTimeEncryptAndThenDecrypt)
{
  // Key = 000102030405060708090A0B0C0D0E0F
  // Nonce = 000102030405060708090A0B0C0D0E0F
  // PT = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  // AD = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
  // TAG = 68915D3F9422289F2349D6A3B4160397
  constexpr auto expected_tag = std::array<char, 2 * ascon_aead128::TAG_BYTE_LEN>{
    '6', '8', '9', '1', '5', 'D', '3', 'F', '9', '4', '2', '2', '2', '8', '9', 'F',
    '2', '3', '4', '9', 'D', '6', 'A', '3', 'B', '4', '1', '6', '0', '3', '9', '7',
  };
  constexpr auto computed_tag = eval_encrypt_decrypt();

  static_assert(expected_tag == computed_tag, "Must be able to encrypt and then decrypt using Ascon-AEAD128 during program compilation time itself !");
}

TEST(AsconAEAD128, EncryptThenDecrypt)
{
  for (size_t associated_data_len = MIN_AD_LEN; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = MIN_PT_LEN; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
      std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};
      std::vector<uint8_t> associated_data(associated_data_len);
      std::vector<uint8_t> plaintext(plaintext_len);
      std::vector<uint8_t> ciphertext(plaintext_len);
      std::vector<uint8_t> decipheredtext(plaintext_len);

      generate_random_data<uint8_t>(key);
      generate_random_data<uint8_t>(nonce);
      generate_random_data<uint8_t>(associated_data);
      generate_random_data<uint8_t>(plaintext);

      ascon_aead128::encrypt(key, nonce, associated_data, plaintext, ciphertext, tag);
      const auto is_decrypted = ascon_aead128::decrypt(key, nonce, associated_data, ciphertext, decipheredtext, tag);

      EXPECT_TRUE(is_decrypted);
      EXPECT_EQ(plaintext, decipheredtext);
    }
  }
}

static void
test_decryption_failure_for_ascon_aead128(const size_t associated_data_len, const size_t plaintext_len, const aead_mutation_kind_t mutation_kind)
{
  EXPECT_GT(associated_data_len, 0);
  EXPECT_GT(plaintext_len, 0);

  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};
  std::vector<uint8_t> associated_data(associated_data_len, 0);
  std::vector<uint8_t> plaintext(plaintext_len, 0);
  std::vector<uint8_t> ciphertext(plaintext_len, 0);
  std::vector<uint8_t> decipheredtext(plaintext_len, 0xff);

  generate_random_data<uint8_t>(key);
  generate_random_data<uint8_t>(nonce);
  generate_random_data<uint8_t>(associated_data);
  generate_random_data<uint8_t>(plaintext);

  ascon_aead128::encrypt(key, nonce, associated_data, plaintext, ciphertext, tag);

  switch (mutation_kind) {
    case aead_mutation_kind_t::mutate_key:
      do_bitflip(key);
      break;
    case aead_mutation_kind_t::mutate_nonce:
      do_bitflip(nonce);
      break;
    case aead_mutation_kind_t::mutate_tag:
      do_bitflip(tag);
      break;
    case aead_mutation_kind_t::mutate_associated_data:
      do_bitflip(associated_data);
      break;
    case aead_mutation_kind_t::mutate_cipher_text:
      do_bitflip(ciphertext);
      break;
    default:
      EXPECT_TRUE(false);
  }

  const auto is_decrypted = ascon_aead128::decrypt(key, nonce, associated_data, ciphertext, decipheredtext, tag);
  EXPECT_FALSE(is_decrypted);

  std::vector<uint8_t> zeros(plaintext_len, 0);
  EXPECT_EQ(decipheredtext, zeros);
}

TEST(AsconAEAD128, DecryptionFailureDueToBitFlippingInKey)
{
  for (size_t associated_data_len = 1; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = 1; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      test_decryption_failure_for_ascon_aead128(associated_data_len, plaintext_len, aead_mutation_kind_t::mutate_key);
    }
  }
}

TEST(AsconAEAD128, DecryptionFailureDueToBitFlippingInNonce)
{
  for (size_t associated_data_len = 1; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = 1; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      test_decryption_failure_for_ascon_aead128(associated_data_len, plaintext_len, aead_mutation_kind_t::mutate_nonce);
    }
  }
}

TEST(AsconAEAD128, DecryptionFailureDueToBitFlippingInTag)
{
  for (size_t associated_data_len = 1; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = 1; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      test_decryption_failure_for_ascon_aead128(associated_data_len, plaintext_len, aead_mutation_kind_t::mutate_tag);
    }
  }
}

TEST(AsconAEAD128, DecryptionFailureDueToBitFlippingInAssociatedData)
{
  for (size_t associated_data_len = 1; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = 1; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      test_decryption_failure_for_ascon_aead128(associated_data_len, plaintext_len, aead_mutation_kind_t::mutate_associated_data);
    }
  }
}

TEST(AsconAEAD128, DecryptionFailureDueToBitFlippingInCipherText)
{
  for (size_t associated_data_len = 1; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = 1; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      test_decryption_failure_for_ascon_aead128(associated_data_len, plaintext_len, aead_mutation_kind_t::mutate_cipher_text);
    }
  }
}
