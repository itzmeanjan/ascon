#pragma once
#include "ascon_hash.hpp"
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test if both oneshot and incremental hashing of same message, using
// Ascon-Hash, produces same digest or not.
inline void
test_ascon_hash(const size_t mlen)
{
  std::vector<uint8_t> digest_oneshot(ascon_hash::DIGEST_LEN);
  std::vector<uint8_t> digest_incremental(ascon_hash::DIGEST_LEN);
  std::vector<uint8_t> msg(mlen);

  ascon_utils::random_data(msg.data(), msg.size());

  // oneshot hashing
  {
    ascon_hash::ascon_hash hasher;

    hasher.absorb(msg.data(), msg.size());
    hasher.finalize();
    hasher.digest(digest_oneshot.data());
  }

  // incremental hashing
  {
    ascon_hash::ascon_hash hasher;

    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(msg[off], 1), mlen - off);

      hasher.absorb(msg.data() + off, elen);
      off += elen;
    }

    hasher.finalize();
    hasher.digest(digest_incremental.data());
  }

  assert(std::ranges::equal(digest_oneshot, digest_incremental));
}

// Ensure that this Ascon-Hash implementation is conformant to the
// specification, using known answer tests.
inline void
test_ascon_hash_kat()
{
  const std::string kat_file = "./kats/ascon_hash.kat";
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

      std::vector<uint8_t> digest(ascon_hash::DIGEST_LEN);

      {
        ascon_hash::ascon_hash hasher;

        hasher.absorb(msg.data(), msg.size());
        hasher.finalize();
        hasher.digest(digest.data());
      }

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
