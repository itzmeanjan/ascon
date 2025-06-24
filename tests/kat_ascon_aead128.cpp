#include "ascon/aead/ascon_aead128.hpp"
#include "test_helper.hpp"
#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>

TEST(AsconAEAD128, KnownAnswerTests)
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_aead128.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string key0;
      std::string nonce0;
      std::string pt0;
      std::string ad0;
      std::string ct0;

      std::getline(file, key0);
      std::getline(file, nonce0);
      std::getline(file, pt0);
      std::getline(file, ad0);
      std::getline(file, ct0);

      auto key1 = std::string_view(key0);
      auto nonce1 = std::string_view(nonce0);
      auto pt1 = std::string_view(pt0);
      auto ad1 = std::string_view(ad0);
      auto ct1 = std::string_view(ct0);

      auto key2 = key1.substr(key1.find("="sv) + 2, key1.size());
      auto nonce2 = nonce1.substr(nonce1.find("="sv) + 2, nonce1.size());
      auto pt2 = ((pt1.find("="sv) + 2) > pt1.size()) ? ""sv : pt1.substr(pt1.find("="sv) + 2, pt1.size());
      auto ad2 = ((ad1.find("="sv) + 2) > ad1.size()) ? ""sv : ad1.substr(ad1.find("="sv) + 2, ad1.size());
      auto ct2 = ct1.substr(ct1.find("="sv) + 2, ct1.size());

      auto key = hex_to_bytes(key2);
      auto nonce = hex_to_bytes(nonce2);
      auto pt = hex_to_bytes(pt2);
      auto ad = hex_to_bytes(ad2);
      auto ct = hex_to_bytes(ct2); // cipher text + tag

      auto key_span = std::span<const uint8_t, ascon_aead128::KEY_BYTE_LEN>(key);
      auto nonce_span = std::span<const uint8_t, ascon_aead128::NONCE_BYTE_LEN>(nonce);
      auto ct_span = std::span(ct);
      auto tag_span = std::span<const uint8_t, ascon_aead128::TAG_BYTE_LEN>(ct_span.last(ascon_aead128::TAG_BYTE_LEN));

      std::vector<uint8_t> computed_ct(pt.size());
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> computed_tag{};
      std::vector<uint8_t> computed_pt(computed_ct.size());

      ascon_aead128::ascon_aead128_t enc_handle(key_span, nonce_span);

      EXPECT_EQ(enc_handle.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(enc_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

      EXPECT_EQ(enc_handle.encrypt_plaintext(pt, computed_ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
      EXPECT_EQ(enc_handle.finalize_encrypt(computed_tag), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

      ascon_aead128::ascon_aead128_t dec_handle(key_span, nonce_span);

      EXPECT_EQ(dec_handle.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(dec_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

      EXPECT_EQ(dec_handle.decrypt_ciphertext(computed_ct, computed_pt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
      EXPECT_EQ(dec_handle.finalize_decrypt(tag_span), ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);

      EXPECT_TRUE(std::ranges::equal(ct_span.first(pt.size()), computed_ct));
      EXPECT_TRUE(std::ranges::equal(tag_span, computed_tag));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconAEAD128, ACVPKnownAnswerTests)
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon_aead128.acvp.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string key0;
      std::string nonce0;
      std::string pt0;
      std::string ad0;
      std::string ct0;
      std::string tag0;
      std::string test_passed0;

      std::getline(file, key0);
      std::getline(file, nonce0);
      std::getline(file, pt0);
      std::getline(file, ad0);
      std::getline(file, ct0);
      std::getline(file, tag0);
      std::getline(file, test_passed0);

      auto key1 = std::string_view(key0);
      auto nonce1 = std::string_view(nonce0);
      auto pt1 = std::string_view(pt0);
      auto ad1 = std::string_view(ad0);
      auto ct1 = std::string_view(ct0);
      auto tag1 = std::string_view(tag0);
      auto test_passed1 = std::string_view(test_passed0);

      auto key2 = key1.substr(key1.find("="sv) + 2, key1.size());
      auto nonce2 = nonce1.substr(nonce1.find("="sv) + 2, nonce1.size());
      auto pt2 = ((pt1.find("="sv) + 2) > pt1.size()) ? ""sv : pt1.substr(pt1.find("="sv) + 2, pt1.size());
      auto ad2 = ((ad1.find("="sv) + 2) > ad1.size()) ? ""sv : ad1.substr(ad1.find("="sv) + 2, ad1.size());
      auto ct2 = ct1.substr(ct1.find("="sv) + 2, ct1.size());
      auto tag2 = tag1.substr(tag1.find("="sv) + 2, tag1.size());
      auto test_passed2 = test_passed1.substr(test_passed1.find("="sv) + 2, test_passed1.size());

      auto key = hex_to_bytes(key2);
      auto nonce = hex_to_bytes(nonce2);
      auto pt = hex_to_bytes(pt2);
      auto ad = hex_to_bytes(ad2);
      auto ct = hex_to_bytes(ct2);
      auto tag = hex_to_bytes(tag2);
      auto test_passed = test_passed2 == "True";

      auto key_span = std::span<const uint8_t, ascon_aead128::KEY_BYTE_LEN>(key);
      auto nonce_span = std::span<const uint8_t, ascon_aead128::NONCE_BYTE_LEN>(nonce);
      auto ct_span = std::span(ct);

      std::vector<uint8_t> computed_ct(pt.size());
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> computed_tag{};
      std::vector<uint8_t> computed_pt(computed_ct.size());
      auto computed_tag_span = std::span(computed_tag);

      ascon_aead128::ascon_aead128_t enc_handle(key_span, nonce_span);

      EXPECT_EQ(enc_handle.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(enc_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

      EXPECT_EQ(enc_handle.encrypt_plaintext(pt, computed_ct), ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
      EXPECT_EQ(enc_handle.finalize_encrypt(computed_tag_span), ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

      ascon_aead128::ascon_aead128_t dec_handle(key_span, nonce_span);

      EXPECT_EQ(dec_handle.absorb_data(ad), ascon_aead128::ascon_aead128_status_t::absorbed_data);
      EXPECT_EQ(dec_handle.finalize_data(), ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);

      EXPECT_EQ(dec_handle.decrypt_ciphertext(computed_ct, computed_pt), ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);
      EXPECT_EQ(dec_handle.finalize_decrypt(computed_tag_span), ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches);

      EXPECT_TRUE(std::ranges::equal(ct_span.first(pt.size()), computed_ct));

      if (test_passed) {
        EXPECT_TRUE(std::ranges::equal(tag, computed_tag_span.first(tag.size())));
      } else {
        EXPECT_FALSE(std::ranges::equal(tag, computed_tag_span.first(tag.size())));
      }

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}
