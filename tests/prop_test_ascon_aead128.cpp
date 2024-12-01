#include "ascon/aead/ascon_aead128.hpp"
#include "test_helper.hpp"
#include <gtest/gtest.h>

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
