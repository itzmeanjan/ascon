#pragma once
#include "ascon_hasha.hpp"
#include <algorithm>
#include <cassert>
#include <fstream>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

using namespace std::literals;

// Test if both oneshot and incremental hashing API of Ascon-HashA produces same
// result for same input message.
inline void
test_ascon_hasha(const size_t mlen)
{
  uint8_t digest_oneshot[ascon::ASCON_HASHA_DIGEST_LEN];
  uint8_t digest_incremental[ascon::ASCON_HASHA_DIGEST_LEN];

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  ascon_utils::random_data(msg, mlen);

  // oneshot hashing
  {
    ascon::ascon_hasha hasher;

    hasher.hash(msg, mlen);
    hasher.digest(digest_oneshot);
  }

  // incremental hashing
  {
    ascon::ascon_hasha<true> hasher;

    size_t off = 0;
    while (off < mlen) {
      // because we don't want to be stuck in an infinite loop if msg[off] = 0
      auto elen = std::min<size_t>(std::max<uint8_t>(msg[off], 1), mlen - off);

      hasher.absorb(msg + off, elen);
      off += elen;
    }

    hasher.finalize();
    hasher.digest(digest_incremental);
  }

  // compare both 32 -bytes digests
  bool flg = false;
  for (size_t i = 0; i < ascon::ASCON_HASHA_DIGEST_LEN; i++) {
    flg |= static_cast<bool>(digest_oneshot[i] ^ digest_incremental[i]);
  }

  std::free(msg);

  assert(!flg);
}

// Ensure that this Ascon-HashA implementation is conformant to the
// specification, using known answer tests.
inline void
test_ascon_hasha_kat()
{
  const std::string kat_file = "./kats/ascon_hasha.kat";
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

      std::vector<uint8_t> digest(ascon::ASCON_HASHA_DIGEST_LEN);

      ascon::ascon_hasha hasher;

      hasher.hash(msg.data(), msg.size());
      hasher.digest(digest.data());

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
