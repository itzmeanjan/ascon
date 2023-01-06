#pragma once
#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Utility functions for Ascon Light Weight Cryptography Implementation
namespace ascon_utils {

// Given a 64 -bit unsigned integer word, this routine swaps byte order and
// returns byte swapped 64 -bit word.
//
// Collects inspiration from https://stackoverflow.com/a/36552262
static inline constexpr uint64_t
bswap64(const uint64_t a)
{
#if defined __GNUG__
  return __builtin_bswap64(a);
#else
  return ((a & 0x00000000000000fful) << 56) |
         ((a & 0x000000000000ff00ul) << 40) |
         ((a & 0x0000000000ff0000ul) << 24) |
         ((a & 0x00000000ff000000ul) << 0x8) |
         ((a & 0x000000ff00000000ul) >> 0x8) |
         ((a & 0x0000ff0000000000ul) >> 24) |
         ((a & 0x00ff000000000000ul) >> 40) |
         ((a & 0xff00000000000000ul) >> 56);
#endif
}

// Given big-endian byte array of length 8, this function interprets it as
// 64 -bit unsigned integer
inline uint64_t
from_be_bytes(const uint8_t* const i_bytes)
{
  uint64_t res = 0ul;
  std::memcpy(&res, i_bytes, 8);

  if constexpr (std::endian::native == std::endian::little) {
    return bswap64(res);
  } else {
    return res;
  }
}

// Given a 64 -bit unsigned integer, this function interprets it as a big-endian
// byte array
inline void
to_be_bytes(const uint64_t num, uint8_t* const bytes)
{
  if constexpr (std::endian::native == std::endian::little) {
    const uint64_t res = bswap64(num);
    std::memcpy(bytes, &res, 8);
  } else {
    std::memcpy(bytes, &num, 8);
  }
}

// Generate `len` -many random sampled data of type T | T = unsigned integer
template<typename T>
inline void
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
inline uint64_t
pad_data(const uint8_t* const data, const size_t pad_byte_len)
{
  const size_t dlen = 8ul - pad_byte_len;
  const size_t pad_bit_len = pad_byte_len << 3;
  const size_t pad_mask = 1ul << (pad_bit_len - 1ul);

  uint64_t res = 0ul;
  std::memcpy(&res, data, dlen);

  if constexpr (std::endian::native == std::endian::little) {
    res = bswap64(res);
  }

  return res | pad_mask;
}

// Pad data, when rate = 128, such that padded data (bit-) length is evenly
// divisible by rate ( = 128 ).
//
// See Ascon-128a padding rule in section 2.4.{2,3} of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
inline void
pad_data(
  const uint8_t* const __restrict data,
  const size_t pad_byte_len,
  uint64_t* const __restrict data_blk // padded block; assert len(data_blk) = 2
)
{
  std::memset(data_blk, 0, 16);

  const size_t dlen = 16ul - pad_byte_len;
  const size_t fw_len = std::min(dlen, 8ul);
  const size_t sw_len = dlen - fw_len;

  std::memcpy(&data_blk[0], data, fw_len);
  std::memcpy(&data_blk[1], data + fw_len, sw_len);

  if constexpr (std::endian::native == std::endian::little) {
    data_blk[0] = bswap64(data_blk[0]);
    data_blk[1] = bswap64(data_blk[1]);
  }

  const bool flg = pad_byte_len > 8;
  const size_t pad_bit_len = (pad_byte_len - 8 * flg) << 3;
  const size_t pad_mask = 1ul << (pad_bit_len - 1ul);

  data_blk[!flg] |= pad_mask;
}

// Converts byte array into hex string; see https://stackoverflow.com/a/14051107
inline const std::string
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
