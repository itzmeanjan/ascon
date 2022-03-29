#pragma once
#include <cstdint>

// Utility functions for Ascon Light Weight Cryptography Implementation
namespace ascon_utils {

// Given big-endian byte array of length 8, this function interprets it as
// 64 -bit unsigned integer
static inline const uint64_t
from_be_bytes(const uint8_t* const i_bytes)
{
  return (static_cast<uint64_t>(i_bytes[0]) << 56) |
         (static_cast<uint64_t>(i_bytes[1]) << 48) |
         (static_cast<uint64_t>(i_bytes[2]) << 40) |
         (static_cast<uint64_t>(i_bytes[3]) << 32) |
         (static_cast<uint64_t>(i_bytes[4]) << 24) |
         (static_cast<uint64_t>(i_bytes[5]) << 16) |
         (static_cast<uint64_t>(i_bytes[6]) << 8) |
         static_cast<uint64_t>(i_bytes[7]);
}

// Given a 64 -bit unsigned integer, this function interprets it as a big-endian
// byte array
static inline void
to_be_bytes(const uint64_t num, uint8_t* const bytes)
{
#pragma unroll 8
  for (size_t i = 0; i < 8; i++) {
    bytes[i] = static_cast<uint8_t>(num >> ((8u - (i + 1u)) << 3u));
  }
}

// Binary logarithm of n, when n = 2 ^ i | i = {1, 2, 3, ...}; taken from
// https://github.com/itzmeanjan/blake3-fpga/blob/a9aa7371ad492c5b01c4aa060982502acbbdef67/include/blake3.hpp#L33-L45
static inline const size_t
bin_log(size_t n)
{
  size_t cnt = 0ul;

  while (n > 1ul) {
    n >>= 1;
    cnt++;
  }

  return cnt;
}

}
