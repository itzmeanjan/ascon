#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

// Min. and max. byte length of associated data.
constexpr size_t MIN_AD_LEN = 0;
constexpr size_t MAX_AD_LEN = 64;

// Min. and max. byte length of plain/ cipher text.
constexpr size_t MIN_CT_LEN = 0;
constexpr size_t MAX_CT_LEN = 128;

// Min. and max. byte length of message to be absorbed into sponge.
constexpr size_t MIN_MSG_LEN = 0;
constexpr size_t MAX_MSG_LEN = 1024;

// Min. and max. byte length of output to be squeezed from sponge.
constexpr size_t MIN_OUT_LEN = 0;
constexpr size_t MAX_OUT_LEN = 256;

// Given a byte array of length L, this routine can be used for interpreting those bytes
// as a hex-encoded string of length 2*L.
template<size_t L>
constexpr std::array<char, L * 2>
bytes_to_hex(std::array<uint8_t, L> bytes)
{
  constexpr std::array<char, 16> table{ '0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  std::array<char, bytes.size() * 2> hex{};

  for (size_t i = 0; i < bytes.size(); i++) {
    hex[2 * i + 0] = table[bytes[i] >> 4];
    hex[2 * i + 1] = table[bytes[i] & 0x0f];
  }

  return hex;
}
