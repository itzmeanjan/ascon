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
#include <span>
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
    return ((a & 0x00000000000000fful) << 56) | ((a & 0x000000000000ff00ul) << 40) |
           ((a & 0x0000000000ff0000ul) << 24) | ((a & 0x00000000ff000000ul) << 0x8) |
           ((a & 0x000000ff00000000ul) >> 0x8) | ((a & 0x0000ff0000000000ul) >> 24) |
           ((a & 0x00ff000000000000ul) >> 40) | ((a & 0xff00000000000000ul) >> 56);
#endif
  }
}

// Given big-endian byte array of length 4/ 8, this function interprets it as
// 32/ 64 -bit unsigned integer.
template<typename T>
inline T
from_be_bytes(std::span<const uint8_t> bytes)
  requires(std::unsigned_integral<T> && ((sizeof(T) == 4) || (sizeof(T) == 8)))
{
  T res = 0;
  std::memcpy(&res, bytes.data(), bytes.size());

  if constexpr (std::endian::native == std::endian::little) {
    return bswap(res);
  } else {
    return res;
  }
}

// Given a 32/ 64 -bit unsigned integer, this function interprets it as a
// big-endian byte array of length 4/ 8.
template<typename T>
inline void
to_be_bytes(const T num, std::span<uint8_t> bytes)
  requires(std::unsigned_integral<T> && ((sizeof(T) == 4) || (sizeof(T) == 8)))
{
  if constexpr (std::endian::native == std::endian::little) {
    const auto res = bswap(num);
    std::memcpy(bytes.data(), &res, sizeof(T));
  } else {
    std::memcpy(bytes.data(), &num, sizeof(T));
  }
}

// Given a N (>=0) -bytes message, this routine can be used for extracting at
// max `len` -bytes chunk, which is (zero based indexing) indexed by `i` s.t. i ∈ [0,
// (mlen + len - 1)/ len). Note, it's possible that very last chunk of message may not
// have `len` -bytes to fill up the full chunk. This function returns how many bytes
// were actually read for this chunk, which must ∈ [0, len]. And it doesn't touch
// remaining bytes of chunk, if they can't be filled up. It's caller's responsibility to
// take proper care of them, before using the message chunk, as it may be some garbage
// bytes from previous iteration.
template<const size_t len>
inline size_t
get_ith_msg_blk(
  std::span<const uint8_t> msg,   // chunk(s) to be read from this message
  const size_t i,                 // index of message chunk, to be read
  std::span<uint8_t, len> msg_blk // len -bytes chunk to be (partially) filled
)
{
  // This routine makes an assumption that function caller invokes it with such
  // `i` value that off <= msg.size()
  const size_t off = i * len;
  const size_t readable = std::min(len, msg.size() - off);

  std::memcpy(msg_blk.data(), msg.data() + off, readable);
  return readable;
}

// Padding a message block of `len` -bytes, following 10* rule s.t. first `used` -many
// bytes are filled and they can't be touched.
template<const size_t len>
inline void
pad_msg_blk(std::span<uint8_t, len> msg_blk, const size_t used)
{
  std::memset(msg_blk.data() + used, 0x00, len - used);
  std::memset(msg_blk.data() + used, 0x80, std::min(len - used, 1ul));
}

// Converts byte array into hex string; see https://stackoverflow.com/a/14051107
inline const std::string
to_hex(std::span<const uint8_t> bytes)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < bytes.size(); i++) {
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
template<const size_t len>
inline constexpr uint32_t
ct_eq_byte_array(std::span<const uint8_t, len> byte_arr_a,
                 std::span<const uint8_t, len> byte_arr_b)
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
                      std::span<uint8_t> byte_arr,
                      const uint8_t val)
{
  for (size_t i = 0; i < byte_arr.size(); i++) {
    byte_arr[i] = subtle::ct_select(cond, val, byte_arr[i]);
  }
}

// Generate `len` -many random sampled data of type T | T = unsigned integer.
//
// **Not cryptographically secure !**
template<typename T>
inline void
random_data(std::span<T> data)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<T> dis;

  for (size_t i = 0; i < data.size(); i++) {
    data[i] = dis(gen);
  }
}

}
