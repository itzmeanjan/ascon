#include "ascon_perm.hpp"
#include "hashing/ascon_hash.hpp"
#include "hashing/ascon_hasha.hpp"
#include "hashing/ascon_xof.hpp"
#include "hashing/ascon_xofa.hpp"
#include <array>
#include <gtest/gtest.h>

// See section 2.5.1 of Ascon v1.2 spec.
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf for following test
// cases.

// Apply 12 -rounds Ascon permutation instance on 320 -bit permutation state s.t. first
// 64 -bits are provided as input and remaining 256 -bits are set to zero.
inline constexpr ascon_perm::ascon_perm_t
apply_permutation(const uint64_t row0)
{
  ascon_perm::ascon_perm_t state({ row0, 0, 0, 0, 0 });
  state.permute<ascon_perm::MAX_ROUNDS>();
  return state;
}

TEST(AsconPermutation, AsconPermWithAsconHashIV)
{
  constexpr bool res = apply_permutation(ascon_hash::IV).reveal() ==
                       std::array<uint64_t, 5>{ 0xee9398aadb67f03dul,
                                                0x8bb21831c60f1002ul,
                                                0xb48a92db98d5da62ul,
                                                0x43189921b8f8e3e8ul,
                                                0x348fa5c9d525e140ul };
  static_assert(res, "Must compute init state of Ascon-Hash, in compile-time !");
  ASSERT_TRUE(res);
}

TEST(AsconPermutation, AsconPermWithAsconHashAIV)
{
  constexpr bool res = apply_permutation(ascon_hasha::IV).reveal() ==
                       std::array<uint64_t, 5>{ 0x01470194fc6528a6,
                                                0x738ec38ac0adffa7,
                                                0x2ec8e3296c76384c,
                                                0xd6f6a54d7f52377d,
                                                0xa13c42a223be8d87 };
  static_assert(res, "Must compute init state of Ascon-HashA, in compile-time !");
  ASSERT_TRUE(res);
}

TEST(AsconPermutation, AsconPermWithAsconXofIV)
{
  constexpr bool res = apply_permutation(ascon_xof::IV).reveal() ==
                       std::array<uint64_t, 5>{ 0xb57e273b814cd416,
                                                0x2b51042562ae2420,
                                                0x66a3a7768ddf2218,
                                                0x5aad0a7a8153650c,
                                                0x4f3e0e32539493b6 };
  static_assert(res, "Must compute init state of Ascon-Xof, in compile-time !");
  ASSERT_TRUE(res);
}

TEST(AsconPermutation, AsconPermWithAsconXofAIV)
{
  constexpr bool res = apply_permutation(ascon_xofa::IV).reveal() ==
                       std::array<uint64_t, 5>{ 0x44906568b77b9832,
                                                0xcd8d6cae53455532,
                                                0xf7b5212756422129,
                                                0x246885e1de0d225b,
                                                0xa8cb5ce33449973f };
  static_assert(res, "Must compute init state of Ascon-XofA, in compile-time !");
  ASSERT_TRUE(res);
}
