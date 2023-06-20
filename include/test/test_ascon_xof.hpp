#pragma once
#include "ascon_xof.hpp"
#include <algorithm>
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test if both oneshot and incremental hashing API of Ascon-Xof produces same
// result for same input message.
inline void
test_ascon_xof(const size_t mlen, const size_t dlen)
{
  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto dig_oneshot = static_cast<uint8_t*>(std::malloc(dlen));
  auto dig_incremental = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  // oneshot hashing
  {
    ascon::ascon_xof hasher;

    // absorb all message bytes at once
    hasher.hash(msg, mlen);
    // squeeze all digest bytes at once
    hasher.read(dig_oneshot, dlen);
  }

  // incremental hashing
  {
    ascon::ascon_xof<true> hasher;

    // absorb message bytes in many iterations
    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(msg[off], 1), mlen - off);

      hasher.absorb(msg + off, elen);
      off += elen;
    }

    // finalize absorption of message bytes
    hasher.finalize();

    // squeeze message bytes in many iterations
    off = 0;
    while (off < dlen) {
      hasher.read(dig_incremental + off, 1);

      auto elen = std::min<size_t>(dig_incremental[off], dlen - (off + 1));

      off += 1;
      hasher.read(dig_incremental + off, elen);
      off += elen;
    }
  }

  // ensure that both techniques produce same digest bytes !
  bool flg = false;
  for (size_t i = 0; i < dlen; i++) {
    flg |= static_cast<bool>(dig_oneshot[i] ^ dig_incremental[i]);
  }

  std::free(msg);
  std::free(dig_oneshot);
  std::free(dig_incremental);

  assert(!flg);
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

      ascon::ascon_xof hasher;

      hasher.hash(msg.data(), msg.size());
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
