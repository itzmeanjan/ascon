#pragma once
#include "ascon_xof.hpp"
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test if both oneshot and incremental hashing of same message, using
// Ascon-Xof, produces same output bytes or not.
inline void
test_ascon_xof(const size_t mlen, const size_t dlen)
{
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig_oneshot(dlen);
  std::vector<uint8_t> dig_incremental(dlen);

  ascon_utils::random_data(msg.data(), msg.size());

  // oneshot hashing
  {
    ascon_xof::ascon_xof hasher;

    hasher.absorb(msg.data(), msg.size());
    hasher.finalize();
    hasher.read(dig_oneshot.data(), dig_oneshot.size());
  }

  // incremental hashing
  {
    ascon_xof::ascon_xof hasher;

    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(msg[off], 1), mlen - off);

      hasher.absorb(msg.data() + off, elen);
      off += elen;
    }

    hasher.finalize();

    // squeeze message bytes in many iterations
    off = 0;
    while (off < dlen) {
      hasher.read(dig_incremental.data() + off, 1);

      auto elen = std::min<size_t>(dig_incremental[off], dlen - (off + 1));

      off += 1;
      hasher.read(dig_incremental.data() + off, elen);
      off += elen;
    }
  }

  assert(std::ranges::equal(dig_oneshot, dig_incremental));
}

// Ensure that this Ascon-Xof implementation is conformant to the
// specification, using known answer tests.
inline void
test_ascon_xof_kat()
{
  const std::string kat_file = "./kats/ascon_xof.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string count0;

    if (!std::getline(file, count0).eof()) {
      std::string msg0;
      std::string md0;

      std::getline(file, msg0);
      std::getline(file, md0);

      auto msg1 = std::string_view(msg0);
      auto md1 = std::string_view(md0);

      auto msg2 = msg1.substr(msg1.find("="sv) + 2, msg1.size());
      auto md2 = md1.substr(md1.find("="sv) + 2, md1.size());

      auto msg = ascon_utils::from_hex(msg2);
      auto md = ascon_utils::from_hex(md2);

      std::vector<uint8_t> digest(md.size());

      ascon_xof::ascon_xof hasher;

      hasher.absorb(msg.data(), msg.size());
      hasher.finalize();
      hasher.read(digest.data(), digest.size());

      assert(std::ranges::equal(digest, md));

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

}
