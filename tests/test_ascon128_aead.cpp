#include "aead/ascon128.hpp"
#include <fstream>
#include <gtest/gtest.h>
#include <span>

// Test functional correctness of Ascon-128 authenticated encryption and
// verified decryption implementation for different combination of input sizes.
inline void
test_ascon128_aead(const size_t dlen, // bytes; >= 0
                   const size_t ctlen // bytes; >= 0
)
{
  using namespace std::literals;

  std::vector<uint8_t> key(ascon128_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon128_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon128_aead::TAG_LEN);
  std::vector<uint8_t> data(dlen);
  std::vector<uint8_t> text(ctlen);
  std::vector<uint8_t> enc(ctlen);
  std::vector<uint8_t> dec(ctlen);

  auto _key = std::span<uint8_t, ascon128_aead::KEY_LEN>(key);
  auto _nonce = std::span<uint8_t, ascon128_aead::NONCE_LEN>(nonce);
  auto _tag = std::span<uint8_t, ascon128_aead::TAG_LEN>(tag);
  auto _data = std::span(data);
  auto _text = std::span(text);
  auto _enc = std::span(enc);
  auto _dec = std::span(dec);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data<uint8_t>(_nonce);
  ascon_utils::random_data(_data);
  ascon_utils::random_data(_text);

  ascon128_aead::encrypt(_key, _nonce, _data, _text, _enc, _tag);
  bool flag = ascon128_aead::decrypt(_key, _nonce, _data, _enc, _dec, _tag);

  ASSERT_TRUE(flag);
  ASSERT_EQ(_text, _dec);
}

TEST(AsconAEAD, CorrectnessTestAscon128AEAD)
{
  for (size_t dlen = 0; dlen <= 32; dlen++) {
    for (size_t ctlen = 0; ctlen <= 32; ctlen++) {
      test_ascon128_aead(dlen, ctlen);
    }
  }
}

// Ensure that Ascon-128 AEAD implementation conforms to the specification,
// by testing using Known Answer Tests.
inline void
kat_ascon128_aead()
{
  using namespace std::literals;

  const std::string kat_file = "./kats/ascon128_aead.kat";
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
      auto pt2 = pt1.substr(pt1.find("="sv) + 2, pt1.size());
      auto ad2 = ad1.substr(ad1.find("="sv) + 2, ad1.size());
      auto ct2 = ct1.substr(ct1.find("="sv) + 2, ct1.size());

      auto key = ascon_utils::from_hex(key2);
      auto nonce = ascon_utils::from_hex(nonce2);
      auto pt = ascon_utils::from_hex(pt2);
      auto ad = ascon_utils::from_hex(ad2);
      auto ct = ascon_utils::from_hex(ct2);

      auto _key = std::span<uint8_t, ascon128_aead::KEY_LEN>(key);
      auto _nonce = std::span<uint8_t, ascon128_aead::NONCE_LEN>(nonce);
      auto _ad = std::span(ad);
      auto _pt = std::span(pt);
      auto _ct = std::span(ct);

      std::vector<uint8_t> ctxt(pt.size());
      std::vector<uint8_t> tag(ascon128_aead::TAG_LEN);
      std::vector<uint8_t> ptxt(ctxt.size());

      auto _ctxt = std::span(ctxt);
      auto _tag = std::span<uint8_t, ascon128_aead::TAG_LEN>(tag);
      auto _ptxt = std::span(ptxt);

      ascon128_aead::encrypt(_key, _nonce, _ad, _pt, _ctxt, _tag);
      bool flag = ascon128_aead::decrypt(_key, _nonce, _ad, _ctxt, _ptxt, _tag);

      ASSERT_TRUE(flag);
      ASSERT_EQ(_ct.subspan(0, pt.size()), _ctxt);
      ASSERT_EQ(_ct.subspan(pt.size()), _tag);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(AsconAEAD, KnownAnswerTestsAscon128AEAD)
{
  kat_ascon128_aead();
}
