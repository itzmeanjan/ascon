#include "ascon/aead/ascon_aead128.hpp"
#include "test_helper.hpp"
#include <algorithm>
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

  ascon_aead128::ascon_aead128_t enc_handle(key, nonce);
  assert(enc_handle.absorb_data(associated_data) == ascon_aead128::ascon_aead128_status_t::absorbed_data);
  assert(enc_handle.finalize_data() == ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  assert(enc_handle.encrypt_plaintext(plain_text, cipher_text) == ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  assert(enc_handle.finalize_encrypt(tag) == ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

  ascon_aead128::ascon_aead128_t dec_handle(key, nonce);
  assert(dec_handle.absorb_data(associated_data) == ascon_aead128::ascon_aead128_status_t::absorbed_data);
  assert(dec_handle.finalize_data() == ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  assert(dec_handle.decrypt_ciphertext(cipher_text, deciphered_text) == ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  assert(dec_handle.finalize_decrypt(tag) == ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);

  assert(plain_text == deciphered_text);
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

      ascon_aead128::ascon_aead128_t enc_handle(key, nonce);
      EXPECT_EQ(enc_handle.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(enc_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(enc_handle.encrypt_plaintext(plaintext, ciphertext), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
      EXPECT_EQ(enc_handle.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

      ascon_aead128::ascon_aead128_t dec_handle(key, nonce);
      EXPECT_EQ(dec_handle.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(dec_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(dec_handle.decrypt_ciphertext(ciphertext, decipheredtext), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
      EXPECT_EQ(dec_handle.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);

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
  std::vector<uint8_t> decipheredtext(plaintext_len, 0);

  generate_random_data<uint8_t>(key);
  generate_random_data<uint8_t>(nonce);
  generate_random_data<uint8_t>(associated_data);
  generate_random_data<uint8_t>(plaintext);

  ascon_aead128::ascon_aead128_t enc_handle(key, nonce);
  EXPECT_EQ(enc_handle.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(enc_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(enc_handle.encrypt_plaintext(plaintext, ciphertext), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(enc_handle.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

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

  ascon_aead128::ascon_aead128_t dec_handle(key, nonce);
  EXPECT_EQ(dec_handle.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(dec_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(dec_handle.decrypt_ciphertext(ciphertext, decipheredtext), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(dec_handle.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch);
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

TEST(AsconAEAD128, ForSamePlaintextOneshotEncryptionAndIncrementalEncryptionProducesSameTag)
{
  for (size_t associated_data_len = MIN_AD_LEN; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = MIN_PT_LEN; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
      std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag_oneshot{};
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag_multishot{};
      std::vector<uint8_t> associated_data(associated_data_len);
      std::vector<uint8_t> plaintext(plaintext_len);
      std::vector<uint8_t> ciphertext(plaintext_len);
      std::vector<uint8_t> decipheredtext(plaintext_len);

      generate_random_data<uint8_t>(key);
      generate_random_data<uint8_t>(nonce);
      generate_random_data<uint8_t>(associated_data);
      generate_random_data<uint8_t>(plaintext);

      tag_oneshot.fill(0x3f);
      tag_multishot.fill(0x5f);

      auto associated_data_span = std::span(associated_data);
      auto plaintext_span = std::span(plaintext);
      auto ciphertext_span = std::span(ciphertext);

      // Oneshot encryption
      {
        ascon_aead128::ascon_aead128_t aead(key, nonce);

        EXPECT_EQ(aead.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
        EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
        EXPECT_EQ(aead.encrypt_plaintext(plaintext, ciphertext), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
        EXPECT_EQ(aead.finalize_encrypt(tag_oneshot), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
      }

      std::ranges::fill(ciphertext, 0x00);

      // Incremental encryption
      {
        ascon_aead128::ascon_aead128_t aead(key, nonce);

        size_t ad_offset = 0;
        while (ad_offset < associated_data.size()) {
          // Because we don't want to be stuck in an infinite loop if associated_data[ad_offset] = 0
          const auto elen = std::min<size_t>(std::max<uint8_t>(associated_data[ad_offset], 1), associated_data.size() - ad_offset);

          auto ad = associated_data_span.subspan(ad_offset, elen);

          EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
          ad_offset += elen;
        }

        EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

        size_t pt_offset = 0;
        while (pt_offset < plaintext.size()) {
          // Because we don't want to be stuck in an infinite loop if plaintext[pt_offset] = 0
          const auto elen = std::min<size_t>(std::max<uint8_t>(plaintext[pt_offset], 1), plaintext.size() - pt_offset);

          auto pt = plaintext_span.subspan(pt_offset, elen);
          auto ct = ciphertext_span.subspan(pt_offset, elen);

          EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
          pt_offset += elen;
        }

        EXPECT_EQ(aead.finalize_encrypt(tag_multishot), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
      }

      EXPECT_EQ(tag_oneshot, tag_multishot);
    }
  }
}

TEST(AsconAEAD128, ForSameCiphertextOneshotDecryptionAndIncrementalDecryptionProducesSamePlaintext)
{
  for (size_t associated_data_len = MIN_AD_LEN; associated_data_len <= MAX_AD_LEN; associated_data_len++) {
    for (size_t plaintext_len = MIN_PT_LEN; plaintext_len <= MAX_PT_LEN; plaintext_len++) {
      std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
      std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};
      std::vector<uint8_t> associated_data(associated_data_len);
      std::vector<uint8_t> plaintext(plaintext_len);
      std::vector<uint8_t> ciphertext(plaintext_len);
      std::vector<uint8_t> decipheredtext_oneshot(plaintext_len);
      std::vector<uint8_t> decipheredtext_multishot(plaintext_len);

      generate_random_data<uint8_t>(key);
      generate_random_data<uint8_t>(nonce);
      generate_random_data<uint8_t>(associated_data);
      generate_random_data<uint8_t>(plaintext);

      std::ranges::fill(decipheredtext_oneshot, 0x3f);
      std::ranges::fill(decipheredtext_multishot, 0x5f);

      auto associated_data_span = std::span(associated_data);
      auto ciphertext_span = std::span(ciphertext);
      auto decipheredtext_oneshot_span = std::span(decipheredtext_oneshot);
      auto decipheredtext_multishot_span = std::span(decipheredtext_multishot);

      ascon_aead128::ascon_aead128_t enc_obj(key, nonce);

      EXPECT_EQ(enc_obj.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(enc_obj.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
      EXPECT_EQ(enc_obj.encrypt_plaintext(plaintext, ciphertext), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
      EXPECT_EQ(enc_obj.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

      // Oneshot decryption
      {
        ascon_aead128::ascon_aead128_t aead(key, nonce);

        EXPECT_EQ(aead.absorb_data(associated_data), ascon_aead128::ascon_aead128_status_t::absorbed_data);
        EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
        EXPECT_EQ(aead.decrypt_ciphertext(ciphertext, decipheredtext_oneshot_span), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
        EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);
      }

      // Incremental decryption
      {
        ascon_aead128::ascon_aead128_t aead(key, nonce);

        size_t ad_offset = 0;
        while (ad_offset < associated_data.size()) {
          // Because we don't want to be stuck in an infinite loop if associated_data[ad_offset] = 0
          const auto elen = std::min<size_t>(std::max<uint8_t>(associated_data[ad_offset], 1), associated_data.size() - ad_offset);

          auto ad = associated_data_span.subspan(ad_offset, elen);

          EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
          ad_offset += elen;
        }

        EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

        size_t ct_offset = 0;
        while (ct_offset < ciphertext.size()) {
          // Because we don't want to be stuck in an infinite loop if ciphertext[ct_offset] = 0
          const auto elen = std::min<size_t>(std::max<uint8_t>(ciphertext[ct_offset], 1), ciphertext.size() - ct_offset);

          auto ct = ciphertext_span.subspan(ct_offset, elen);
          auto dt = decipheredtext_multishot_span.subspan(ct_offset, elen);

          EXPECT_EQ(aead.decrypt_ciphertext(ct, dt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
          ct_offset += elen;
        }

        EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);
      }

      EXPECT_EQ(decipheredtext_oneshot, plaintext);
      EXPECT_EQ(decipheredtext_oneshot, decipheredtext_multishot);
    }
  }
}

static ascon_aead128::ascon_aead128_t
get_new_aead_instance()
{
  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};

  generate_random_data<uint8_t>(key);
  generate_random_data<uint8_t>(nonce);

  ascon_aead128::ascon_aead128_t aead(key, nonce);
  return aead;
}

TEST(AsconAEAD128, ValidEncryptionSequence)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
}

TEST(AsconAEAD128, ValidDecryptionSequence)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.decrypt_ciphertext(ct, pt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch);
}

TEST(AsconAEAD128, MultipleAbsorbDataCalls)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 8> ad1{};
  std::array<uint8_t, 8> ad2{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad1), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.absorb_data(ad2), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
}

TEST(AsconAEAD128, MultipleEncryptPlaintextCalls)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 8> pt1{};
  std::array<uint8_t, 8> pt2{};
  std::array<uint8_t, 8> ct1{};
  std::array<uint8_t, 8> ct2{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt1, ct1), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.encrypt_plaintext(pt2, ct2), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
}

TEST(AsconAEAD128, MultipleDecryptCiphertextCalls)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 8> ct1{};
  std::array<uint8_t, 8> ct2{};
  std::array<uint8_t, 8> pt1{};
  std::array<uint8_t, 8> pt2{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.decrypt_ciphertext(ct1, pt1), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.decrypt_ciphertext(ct2, pt2), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch);
}

TEST(AsconAEAD128, AbsorbDataAfterFinalizeData)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad1{};
  std::array<uint8_t, 16> ad2{};

  EXPECT_EQ(aead.absorb_data(ad1), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.absorb_data(ad2), ascon_aead128::ascon_aead128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconAEAD128, FinalizeDataCalledTwice)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconAEAD128, EncryptPlaintextBeforeFinalizeData)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
}

TEST(AsconAEAD128, DecryptCiphertextBeforeFinalizeData)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, 16> pt{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.decrypt_ciphertext(ct, pt), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
}

TEST(AsconAEAD128, FinalizeEncryptBeforeFinalizeData)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
  EXPECT_EQ(aead.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
}

TEST(AsconAEAD128, FinalizeDecryptBeforeFinalizeData)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.decrypt_ciphertext(ct, pt), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
  EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::still_in_data_absorption_phase);
}

TEST(AsconAEAD128, EncryptPlaintextAfterFinalizeEncrypt)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt1{};
  std::array<uint8_t, 16> pt2{};
  std::array<uint8_t, 16> ct1{};
  std::array<uint8_t, 16> ct2{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt1, ct1), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.finalize_encrypt(tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt2, ct2), ascon_aead128::ascon_aead128_status_t::encryption_phase_already_finalized);
}

TEST(AsconAEAD128, DecryptCiphertextAfterFinalizeDecrypt)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct1{};
  std::array<uint8_t, 16> ct2{};
  std::array<uint8_t, 16> pt1{};
  std::array<uint8_t, 16> pt2{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.decrypt_ciphertext(ct1, pt1), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.finalize_decrypt(tag), ascon_aead128::ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch);
  EXPECT_EQ(aead.decrypt_ciphertext(ct2, pt2), ascon_aead128::ascon_aead128_status_t::decryption_phase_already_finalized);
}

TEST(AsconAEAD128, FinalizeEncryptCalledTwice)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag1{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag2{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.finalize_encrypt(tag1), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);
  EXPECT_EQ(aead.finalize_encrypt(tag2), ascon_aead128::ascon_aead128_status_t::encryption_phase_already_finalized);
}

TEST(AsconAEAD128, FinalizeDecryptCalledTwice)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag1{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag2{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.decrypt_ciphertext(ct, pt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.finalize_decrypt(tag1), ascon_aead128::ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch);
  EXPECT_EQ(aead.finalize_decrypt(tag2), ascon_aead128::ascon_aead128_status_t::decryption_phase_already_finalized);
}

TEST(AsconAEAD128, AbsorbDataAfterEncrypt)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> pt{};
  std::array<uint8_t, 16> ct{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.encrypt_plaintext(pt, ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconAEAD128, AbsorbDataAfterDecrypt)
{
  auto aead = get_new_aead_instance();

  std::array<uint8_t, 16> ad{};
  std::array<uint8_t, 16> ct{};
  std::array<uint8_t, 16> pt{};

  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  EXPECT_EQ(aead.decrypt_ciphertext(ct, pt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
  EXPECT_EQ(aead.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::data_absorption_phase_already_finalized);
}

TEST(AsconAEAD128, FinalizeDataWithoutAbsorb)
{
  auto aead = get_new_aead_instance();

  EXPECT_EQ(aead.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
}
