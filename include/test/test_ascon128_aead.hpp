#pragma once
#include "aead.hpp"
#include "auth_enc.hpp"
#include "consts.hpp"
#include "utils.hpp"
#include "verf_dec.hpp"
#include <cassert>
#include <cstdint>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test correctness of Ascon-128 authenticated encryption and verified
// decryption implementation for different input sizes
inline void
ascon128_aead(const size_t dlen, // bytes; >= 0
              const size_t ctlen // bytes; >= 0
)
{
  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dlen));
  auto text = static_cast<uint8_t*>(std::malloc(ctlen));
  auto enc = static_cast<uint8_t*>(std::malloc(ctlen));
  auto dec = static_cast<uint8_t*>(std::malloc(ctlen));

  ascon_utils::random_data(key, ascon::ASCON128_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128_NONCE_LEN);
  ascon_utils::random_data(data, dlen);
  ascon_utils::random_data(text, ctlen);

  ascon::encrypt_128(key, nonce, data, dlen, text, ctlen, enc, tag);
  bool v = ascon::decrypt_128(key, nonce, data, dlen, enc, ctlen, dec, tag);

  // ensures that text has been verifiably decrypted !
  assert(v);
  for (size_t i = 0; i < ctlen; i++) {
    assert(text[i] == dec[i]);
  }

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
  std::free(tag);
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
      std::vector<uint8_t> tag(ascon::ASCON128_TAG_LEN);
      std::vector<uint8_t> ptxt(ctxt.size());

      ascon::encrypt_128(key.data(),
                         nonce.data(),
                         ad.data(),
                         ad.size(),
                         pt.data(),
                         pt.size(),
                         ctxt.data(),
                         tag.data());
      bool flag = ascon::decrypt_128(key.data(),
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
