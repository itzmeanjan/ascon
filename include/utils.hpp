#pragma once
#include <cstdint>

// Given big-endian byte array of length 8, this function interprets it as
// 64 -bit unsigned integer
inline const uint64_t
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
