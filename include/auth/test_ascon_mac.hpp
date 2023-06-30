#pragma once
#include "ascon_mac.hpp"
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Ensure that this Ascon-MAC implementation is conformant to the
// specification, using known answer tests.
inline void
test_ascon_mac_kat()
{
  const std::string kat_file = "./kats/ascon_mac.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string key0;
      std::string msg0;
      std::string tag0;

      std::getline(file, key0);
      std::getline(file, msg0);
      std::getline(file, tag0);

      auto key1 = std::string_view(key0);
      auto msg1 = std::string_view(msg0);
      auto tag1 = std::string_view(tag0);

      auto key2 = key1.substr(key1.find("="sv) + 2, key1.size());
      auto msg2 = msg1.substr(msg1.find("="sv) + 2, msg1.size());
      auto tag2 = tag1.substr(tag1.find("="sv) + 2, tag1.size());

      auto key = ascon_utils::from_hex(key2);
      auto msg = ascon_utils::from_hex(msg2);
      auto tag = ascon_utils::from_hex(tag2);

      std::vector<uint8_t> computed(tag.size());

      ascon_mac::ascon_mac mac(key.data());
      mac.authenticate(msg.data(), msg.size());
      mac.finalize(computed.data());
      bool flg = mac.verify(tag.data(), computed.data());

      assert(flg);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

}
