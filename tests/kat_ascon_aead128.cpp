#include "ascon/aead/ascon_aead128.hpp"
#include "test_helper.hpp"
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

      std::vector<uint8_t> computed_ct(pt.size());
      std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> computed_tag{};
      std::vector<uint8_t> computed_pt(computed_ct.size());

      ascon_aead128::encrypt(key_span, nonce_span, ad, pt, computed_ct, computed_tag);
      const auto is_decrypted = ascon_aead128::decrypt(key_span, nonce_span, ad, computed_ct, computed_pt, computed_tag);

      EXPECT_TRUE(is_decrypted);

      auto ct_span = std::span(ct);

      EXPECT_TRUE(std::ranges::equal(ct_span.first(pt.size()), computed_ct));
      EXPECT_TRUE(std::ranges::equal(ct_span.last(computed_tag.size()), computed_tag));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}
