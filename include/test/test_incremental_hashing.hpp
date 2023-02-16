#pragma once
#include "ascon_hash.hpp"
#include "ascon_hasha.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Test if both oneshot and incremental hashing API of Ascon-Hash produces same
// result for same input message.
void
test_ascon_hash(const size_t mlen)
{
  uint8_t digest_oneshot[ascon::ASCON_HASH_DIGEST_LEN];
  uint8_t digest_incremental[ascon::ASCON_HASH_DIGEST_LEN];

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  ascon_utils::random_data(msg, mlen);

  // oneshot hashing
  {
    ascon::ascon_hash hasher;

    hasher.hash(msg, mlen);
    hasher.digest(digest_oneshot);
  }

  // incremental hashing
  {
    ascon::ascon_hash<true> hasher;

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
  for (size_t i = 0; i < ascon::ASCON_HASH_DIGEST_LEN; i++) {
    flg |= static_cast<bool>(digest_oneshot[i] ^ digest_incremental[i]);
  }

  std::free(msg);

  assert(!flg);
}

// Test if both oneshot and incremental hashing API of Ascon-HashA produces same
// result for same input message.
void
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

}
