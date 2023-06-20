#pragma once
#include "ascon_hash.hpp"
#include "ascon_hasha.hpp"
#include "ascon_xof.hpp"
#include "ascon_xofa.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Test if both oneshot and incremental hashing API of Ascon-XOF produces same
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

// Test if both oneshot and incremental hashing API of Ascon-XOFA produces same
// result for same input message.
inline void
test_ascon_xofa(const size_t mlen, const size_t dlen)
{
  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto dig_oneshot = static_cast<uint8_t*>(std::malloc(dlen));
  auto dig_incremental = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  // oneshot hashing
  {
    ascon::ascon_xofa hasher;

    // absorb all message bytes at once
    hasher.hash(msg, mlen);
    // squeeze all digest bytes at once
    hasher.read(dig_oneshot, dlen);
  }

  // incremental hashing
  {
    ascon::ascon_xofa<true> hasher;

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

}
