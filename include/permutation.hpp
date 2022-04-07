#pragma once
#include <bit>
#include <cstdint>

using size_t = std::size_t;

// Underlying permutation functions ( read `p_a` & `p_b` ) for Ascon
// cryptographic suite
namespace ascon_perm {

// Ascon  permutation round constants; taken from table 4 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t RC[12] = { 0x00000000000000f0ul, 0x00000000000000e1ul,
                              0x00000000000000d2ul, 0x00000000000000c3ul,
                              0x00000000000000b4ul, 0x00000000000000a5ul,
                              0x0000000000000096ul, 0x0000000000000087ul,
                              0x0000000000000078ul, 0x0000000000000069ul,
                              0x000000000000005aul, 0x000000000000004bul };

// Addition of constants step; see section 2.6.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t c_idx>
static inline void
p_c(uint64_t* const state)
{
  state[2] ^= RC[c_idx];
}

// Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken from
// figure 5 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
p_s(uint64_t* const state)
{
  state[0] ^= state[4];
  state[4] ^= state[3];
  state[2] ^= state[1];

  uint64_t t0 = state[1] & ~state[0];
  uint64_t t1 = state[2] & ~state[1];
  uint64_t t2 = state[3] & ~state[2];
  uint64_t t3 = state[4] & ~state[3];
  uint64_t t4 = state[0] & ~state[4];

  state[0] ^= t1;
  state[1] ^= t2;
  state[2] ^= t3;
  state[3] ^= t4;
  state[4] ^= t0;

  state[1] ^= state[0];
  state[0] ^= state[4];
  state[3] ^= state[2];
  state[2] = ~state[2];
}

// Linear diffusion layer; taken from figure 4.b in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
p_l(uint64_t* const state)
{
  using namespace std;

  state[0] = state[0] ^ rotr(state[0], 19) ^ rotr(state[0], 28);
  state[1] = state[1] ^ rotr(state[1], 61) ^ rotr(state[1], 39);
  state[2] = state[2] ^ rotr(state[2], 1) ^ rotr(state[2], 6);
  state[3] = state[3] ^ rotr(state[3], 10) ^ rotr(state[3], 17);
  state[4] = state[4] ^ rotr(state[4], 7) ^ rotr(state[4], 41);
}

// Ascon permutation; taken from section 2.6 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t c_idx>
static inline void
permute(uint64_t* const state)
{
  p_c<c_idx>(state);
  p_s(state);
  p_l(state);
}

// Round count for permutation function `p_a` is always 12; see table 1, 2 Ascon
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline constexpr bool
check_a(const size_t a)
{
  return a == 12;
}

// Permutation p_a to be sequentially applied on state for `a` -many times;
// taken from section 2.6 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t a>
static inline void
p_a(uint64_t* const state) requires(check_a(a))
{
  // for round index & constant index convention, read section 2.6.1 of Ascon
  // specification
  permute<0>(state);
  permute<1>(state);
  permute<2>(state);
  permute<3>(state);
  permute<4>(state);
  permute<5>(state);
  permute<6>(state);
  permute<7>(state);
  permute<8>(state);
  permute<9>(state);
  permute<10>(state);
  permute<11>(state);
}

// Compile-time check that round count for `p_b` permutation is 6
static inline constexpr bool
check_b6(const size_t b)
{
  return b == 6;
}

// Compile-time check that round count for `p_b` permutation is 8
static inline constexpr bool
check_b8(const size_t b)
{
  return b == 8;
}

// Compile-time check that round count for `p_b` permutation is 12
static inline constexpr bool
check_b12(const size_t b)
{
  return b == 12;
}

// Compile-time check that round count for permutation function `p_b` ∈ {6, 8,
// 12}; see table 1, 2 Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline constexpr bool
check_b(const size_t b)
{
  return check_b6(b) || check_b8(b) || check_b12(b);
}

// Permutation p_b to be sequentially applied on state for `b` -many times;
// taken from section 2.6 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t b>
static inline void
p_b(uint64_t* const state) requires(check_b(b))
{
  if (check_b6(b)) {
    permute<6>(state);
    permute<7>(state);
    permute<8>(state);
    permute<9>(state);
    permute<10>(state);
    permute<11>(state);
  } else if (check_b8(b)) {
    permute<4>(state);
    permute<5>(state);
    permute<6>(state);
    permute<7>(state);
    permute<8>(state);
    permute<9>(state);
    permute<10>(state);
    permute<11>(state);
  } else if (check_b12(b)) {
    permute<0>(state);
    permute<1>(state);
    permute<2>(state);
    permute<3>(state);
    permute<4>(state);
    permute<5>(state);
    permute<6>(state);
    permute<7>(state);
    permute<8>(state);
    permute<9>(state);
    permute<10>(state);
    permute<11>(state);
  }
}

}
