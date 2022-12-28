#pragma once
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <type_traits>

// Utility functions for Ascon Light Weight Cryptography Implementation
namespace ascon_utils {

// Given big-endian byte array of length 8, this function interprets it as
// 64 -bit unsigned integer
static inline constexpr uint64_t
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
#if defined __clang__
#pragma unroll 8
#elif defined __GNUG__
#pragma GCC ivdep
#pragma GCC unroll 8
#endif
  for (size_t i = 0; i < 8; i++) {
    bytes[i] = static_cast<uint8_t>(num >> ((7ul - i) << 3u));
  }
}

// Generate `len` -many random sampled data of type T | T = unsigned integer
template<typename T>
static inline void
random_data(T* const data, const size_t len)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<T> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

// Pad data when rate = 64, such that padded data (bit-) length is evenly
// divisible by rate ( = 64 ).
//
// See Ascon-{128, Hash, HashA} padding rule in section 2.4.{2,3} & 2.5.2 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline constexpr uint64_t
pad_data(const uint8_t* const data, const size_t pad_byte_len)
{
  uint64_t data_blk = 0b1ul << ((pad_byte_len << 3) - 1ul);

  const size_t dlen = 8ul - pad_byte_len;
  for (size_t i = 0; i < dlen; i++) {
    data_blk |= static_cast<uint64_t>(data[i]) << ((7ul - i) << 3);
  }

  return data_blk;
}

// Pad data, when rate = 128, such that padded data (bit-) length is evenly
// divisible by rate ( = 128 ).
//
// See Ascon-128a padding rule in section 2.4.{2,3} of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
pad_data(
  const uint8_t* const __restrict data,
  const size_t pad_byte_len,
  uint64_t* const __restrict data_blk // padded block; assert len(data_blk) = 2
)
{
  // Important: Clean memory allocation by putting zero bytes !
  std::memset(data_blk, 0, sizeof(uint64_t) << 1);

  const bool flg0 = pad_byte_len <= 8ul;

  const size_t br0[2] = { pad_byte_len - 8ul, pad_byte_len };
  constexpr size_t br1[2] = { 7ul, 15ul };

  data_blk[flg0] = 0b1ul << ((br0[flg0] << 3) - 1ul);

  const size_t dlen = 16ul - pad_byte_len;

  for (size_t i = 0; i < dlen; i++) {
    const bool flg1 = i >= 8ul;
    data_blk[flg1] |= static_cast<uint64_t>(data[i]) << ((br1[flg1] - i) << 3);
  }
}

// Converts byte array into hex string; see https://stackoverflow.com/a/14051107
static inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }
  return ss.str();
}

}
