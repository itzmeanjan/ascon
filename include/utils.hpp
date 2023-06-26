#pragma once
#include "subtle.hpp"
#include <algorithm>
#include <bit>
#include <cassert>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Utility functions for Ascon Light Weight Cipher Suite Implementation
namespace ascon_utils {

// Given a 32/ 64 -bit unsigned integer word, this routine swaps byte order and
// returns byte swapped 32/ 64 -bit word.
//
// Collects inspiration from https://stackoverflow.com/a/36552262
template<typename T>
static inline constexpr T
bswap(const T a)
  requires(std::unsigned_integral<T> && ((sizeof(T) == 4) || (sizeof(T) == 8)))
{
  if constexpr (sizeof(T) == 4) {
#if defined __GNUG__
    return __builtin_bswap32(a);
#else
    return ((a & 0x000000ffu) << 24) | ((a & 0x0000ff00u) << 8) |
           ((a & 0x00ff0000u) >> 8) | ((a & 0xff000000u) >> 24);
#endif
  } else {
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
}

// Given big-endian byte array of length 4/ 8, this function interprets it as
// 32/ 64 -bit unsigned integer
template<typename T>
inline T
from_be_bytes(const uint8_t* const i_bytes)
  requires(std::unsigned_integral<T> && ((sizeof(T) == 4) || (sizeof(T) == 8)))
{
  T res = 0;
  std::memcpy(&res, i_bytes, sizeof(T));

  if constexpr (std::endian::native == std::endian::little) {
    return bswap(res);
  } else {
    return res;
  }
}

// Given a 32/ 64 -bit unsigned integer, this function interprets it as a
// big-endian byte array of length 4/ 8
template<typename T>
inline void
to_be_bytes(const T num, uint8_t* const bytes)
  requires(std::unsigned_integral<T> && ((sizeof(T) == 4) || (sizeof(T) == 8)))
{
  if constexpr (std::endian::native == std::endian::little) {
    const auto res = bswap(num);
    std::memcpy(bytes, &res, sizeof(T));
  } else {
    std::memcpy(bytes, &num, sizeof(T));
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
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
inline uint64_t
pad64(const uint8_t* const data, const size_t pad_byte_len)
{
  const size_t dlen = 8ul - pad_byte_len;
  const size_t pad_bit_len = pad_byte_len << 3;
  const size_t pad_mask = 1ul << (pad_bit_len - 1ul);

  uint64_t res = 0ul;
  std::memcpy(&res, data, dlen);

  if constexpr (std::endian::native == std::endian::little) {
    res = bswap(res);
  }

  return res | pad_mask;
}

// Pad data, when rate = 128, such that padded data (bit-) length is evenly
// divisible by rate ( = 128 ).
//
// See Ascon-128a padding rule in section 2.4.{2,3} of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
inline std::pair<uint64_t, uint64_t>
pad128(const uint8_t* const __restrict data, const size_t pad_byte_len)
{
  const size_t dlen = 16ul - pad_byte_len;
  const size_t fw_len = std::min(dlen, 8ul);
  const size_t sw_len = dlen - fw_len;

  uint64_t res0 = 0;
  uint64_t res1 = 0;

  std::memcpy(&res0, data, fw_len);
  std::memcpy(&res1, data + fw_len, sw_len);

  if constexpr (std::endian::native == std::endian::little) {
    res0 = bswap(res0);
    res1 = bswap(res1);
  }

  const bool flg = pad_byte_len > 8;
  const size_t pad_bit_len = (pad_byte_len - 8 * flg) << 3;
  const size_t pad_mask = 1ul << (pad_bit_len - 1ul);

  uint64_t br[]{ res0, res1 };
  br[!flg] |= pad_mask;

  return { br[0], br[1] };
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

// Given a hex encoded string of length 2*L, this routine can be used for
// parsing it as a byte array of length L.
//
// Taken from
// https://github.com/itzmeanjan/dilithium/blob/c69d524625375959d4573bb83953da89ec8b829c/include/utils.hpp#L72-L94
inline std::vector<uint8_t>
from_hex(std::string_view hex)
{
  const size_t hlen = hex.length();
  assert(hlen % 2 == 0);

  const size_t blen = hlen / 2;
  std::vector<uint8_t> res(blen, 0);

  for (size_t i = 0; i < blen; i++) {
    const size_t off = i * 2;

    uint8_t byte = 0;
    auto sstr = hex.substr(off, 2);
    std::from_chars(sstr.data(), sstr.data() + 2, byte, 16);

    res[i] = byte;
  }

  return res;
}

// Given two byte arrays of equal length, this routine can be used for checking
// equality of them, in constant-time, returning truth value ( 0xffffffff ), in
// case they are equal. Otherwise it returns 0x00000000, denoting inequality of
// content of two byte arrays.
inline constexpr uint32_t
ct_eq_byte_array(const uint8_t* const __restrict byte_arr_a,
                 const uint8_t* const __restrict byte_arr_b,
                 const size_t len)
{
  uint32_t flag = -1u;
  for (size_t i = 0; i < len; i++) {
    flag &= subtle::ct_eq<uint8_t, uint32_t>(byte_arr_a[i], byte_arr_b[i]);
  }

  return flag;
}

// Given a 32 -bit conditional value ( `cond`, which can take any of
// {0x00000000, 0xffffffff} ), this routine can be used for setting bytes (
// pointed to by `byte_arr` ) to some provided value ( `val` ), in
// constant-time, only if `cond` holds truth value ( = 0xffffffff ). Otherwise,
// it shouldn't mutate bytes.
inline constexpr void
ct_conditional_memset(const uint32_t cond,
                      uint8_t* const __restrict byte_arr,
                      const uint8_t val,
                      const size_t len)
{
  for (size_t i = 0; i < len; i++) {
    byte_arr[i] = subtle::ct_select(cond, val, byte_arr[i]);
  }
}

}
