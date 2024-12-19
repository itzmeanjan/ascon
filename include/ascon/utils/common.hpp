#pragma once
#include "ascon/utils/force_inline.hpp"
#include "subtle.hpp"
#include <cstdint>
#include <cstring>
#include <span>

namespace ascon_common_utils {

// Compile-time evaluated function for computing initial values for Ascon variants.
// See appendix B of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
[[nodiscard]]
forceinline consteval uint64_t
compute_iv(const uint8_t unique_algo_id,
           const uint8_t perm_num_rounds_a,
           const uint8_t perm_num_rounds_b,
           const uint16_t tag_bit_len,
           const uint8_t rate_byte_len)
{
  constexpr uint8_t mask4 = 0b1111u;

  return ((static_cast<uint64_t>(rate_byte_len) << 40) |             // 8 -bits
          (static_cast<uint64_t>(tag_bit_len) << 24) |               // 16 -bits
          (static_cast<uint64_t>(perm_num_rounds_b & mask4) << 20) | // 4 -bits
          (static_cast<uint64_t>(perm_num_rounds_a & mask4) << 16) | // 4 -bits
          (0ul << 8) |                                               // 8 -bits
          static_cast<uint64_t>(unique_algo_id)                      // 8 -bits
  );
}

// Converts a little-endian byte array to a 64-bit unsigned integer.
[[nodiscard]]
forceinline constexpr uint64_t
from_le_bytes(std::span<const uint8_t, 8> bytes)
{
  return (static_cast<uint64_t>(bytes[7]) << 56) | (static_cast<uint64_t>(bytes[6]) << 48) | (static_cast<uint64_t>(bytes[5]) << 40) |
         (static_cast<uint64_t>(bytes[4]) << 32) | (static_cast<uint64_t>(bytes[3]) << 24) | (static_cast<uint64_t>(bytes[2]) << 16) |
         (static_cast<uint64_t>(bytes[1]) << 8) | static_cast<uint64_t>(bytes[0]);
}

// Converts a 64-bit unsigned integer to a little-endian byte array.
forceinline constexpr void
to_le_bytes(const uint64_t num, std::span<uint8_t, sizeof(num)> bytes)
{
  bytes[0] = static_cast<uint8_t>(num >> 0);
  bytes[1] = static_cast<uint8_t>(num >> 8);
  bytes[2] = static_cast<uint8_t>(num >> 16);
  bytes[3] = static_cast<uint8_t>(num >> 24);
  bytes[4] = static_cast<uint8_t>(num >> 32);
  bytes[5] = static_cast<uint8_t>(num >> 40);
  bytes[6] = static_cast<uint8_t>(num >> 48);
  bytes[7] = static_cast<uint8_t>(num >> 56);
}

// Performs a constant-time comparison of two byte arrays of length `len`. Returns all bits set (0xFFFFFFFF) if equal, otherwise all bits clear (0x00000000).
template<const size_t len>
[[nodiscard]]
forceinline constexpr uint32_t
ct_eq_byte_array(std::span<const uint8_t, len> byte_arr_a, std::span<const uint8_t, len> byte_arr_b)
{
  uint32_t flag = -1u;
  for (size_t i = 0; i < len; i++) {
    flag &= subtle::ct_eq<uint8_t, uint32_t>(byte_arr_a[i], byte_arr_b[i]);
  }

  return flag;
}

// Sets the bytes in `byte_arr` to `val` if the 32-bit condition `cond` is 0xFFFFFFFF (true); otherwise, leaves `byte_arr` unchanged.  This operation is
// performed in constant time to prevent timing attacks.
forceinline constexpr void
ct_conditional_memset(const uint32_t cond, std::span<uint8_t> byte_arr, const uint8_t val)
{
  for (size_t i = 0; i < byte_arr.size(); i++) {
    byte_arr[i] = subtle::ct_select(cond, val, byte_arr[i]);
  }
}

}
