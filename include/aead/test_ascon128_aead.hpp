#pragma once
#include "ascon128.hpp"
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test functional correctness of Ascon-128 authenticated encryption and
// verified decryption implementation for different input sizes.
inline void
ascon128_aead(const size_t dlen, // bytes; >= 0
              const size_t ctlen // bytes; >= 0
)
{
  std::vector<uint8_t> key(ascon128_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon128_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon128_aead::TAG_LEN);
  std::vector<uint8_t> data(dlen);
  std::vector<uint8_t> text(ctlen);
  std::vector<uint8_t> enc(ctlen);
  std::vector<uint8_t> dec(ctlen);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(nonce.data(), nonce.size());
  ascon_utils::random_data(data.data(), data.size());
  ascon_utils::random_data(text.data(), text.size());

  ascon128_aead::encrypt(key.data(),
                         nonce.data(),
                         data.data(),
                         data.size(),
                         text.data(),
                         text.size(),
                         enc.data(),
                         tag.data());
  bool flag = ascon128_aead::decrypt(key.data(),
                                     nonce.data(),
                                     data.data(),
                                     data.size(),
                                     enc.data(),
                                     enc.size(),
                                     dec.data(),
                                     tag.data());

  assert(flag);
  assert(std::ranges::equal(text, dec));
}

// Ensure that Ascon-128 AEAD implementation conforms to the specification,
// by testing using Known Answer Tests.
inline void
ascon128_aead_kat()
{
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

      std::vector<uint8_t> ctxt(pt.size());
      std::vector<uint8_t> tag(ascon128_aead::TAG_LEN);
      std::vector<uint8_t> ptxt(ctxt.size());

      ascon128_aead::encrypt(key.data(),
                             nonce.data(),
                             ad.data(),
                             ad.size(),
                             pt.data(),
                             pt.size(),
                             ctxt.data(),
                             tag.data());
      bool flag = ascon128_aead::decrypt(key.data(),
                                         nonce.data(),
                                         ad.data(),
                                         ad.size(),
                                         ctxt.data(),
                                         ctxt.size(),
                                         ptxt.data(),
                                         tag.data());

      assert(flag);
      assert(ascon_utils::ct_eq_byte_array(ctxt.data(), ct.data(), pt.size()));

      auto tag_ = ct.data() + pt.size();
      assert(ascon_utils::ct_eq_byte_array(tag.data(), tag_, tag.size()));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

}
