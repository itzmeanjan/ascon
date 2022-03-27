#pragma once
#include <CL/sycl.hpp>

// Ascon Light Weight Cryptography ( i.e. authenticated encryption and hashing )
// Implementation
namespace ascon {

// Ascon  permutation round constants; taken from table 4 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t RC[12] = { 0x00000000000000f0, 0x00000000000000e1,
                              0x00000000000000d2, 0x00000000000000c3,
                              0x00000000000000b4, 0x00000000000000a5,
                              0x0000000000000096, 0x0000000000000087,
                              0x0000000000000078, 0x0000000000000069,
                              0x000000000000005a, 0x000000000000004b };

// Addition of constants step; see section 2.6.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
p_c(uint64_t* const state, const size_t r_idx)
{
  state[2] ^= RC[r_idx];
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

  uint64_t t0 = state[0];
  uint64_t t1 = state[1];
  uint64_t t2 = state[2];
  uint64_t t3 = state[3];
  uint64_t t4 = state[4];

  t0 = ~t0;
  t1 = ~t1;
  t2 = ~t2;
  t3 = ~t3;
  t4 = ~t4;

  t0 &= state[1];
  t1 &= state[2];
  t2 &= state[3];
  t3 &= state[4];
  t4 &= state[0];

  state[0] ^= t1;
  state[1] ^= t2;
  state[2] ^= t3;
  state[3] ^= t4;
  state[4] ^= t0;

  state[1] ^= state[0];
  state[0] ^= state[4];
  state[3] ^= state[2];
  state[2] ^= state[2];
}

// Just to force compile-time evaluation of template argument to `rotr` function
constexpr bool
check(const size_t n)
{
  return n < 64;
}

// Circular right shift of `x` by `n` bit positions | 0 <= n < 64
template<const size_t n>
static inline const uint64_t
rotr(const uint64_t x) requires(check(n))
{
  return (x >> n) | (x << (64 - n));
}

// Linear diffusion layer; taken from figure 4.b in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
p_l(uint64_t* const state)
{
  state[0] = state[0] ^ rotr<19>(state[0]) ^ rotr<28>(state[0]);
  state[1] = state[1] ^ rotr<61>(state[1]) ^ rotr<39>(state[1]);
  state[2] = state[2] ^ rotr<1>(state[2]) ^ rotr<6>(state[2]);
  state[3] = state[3] ^ rotr<10>(state[3]) ^ rotr<17>(state[3]);
  state[4] = state[4] ^ rotr<7>(state[4]) ^ rotr<41>(state[4]);
}

// Ascon permutation; taken from section 2.6 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
permute(uint64_t* const state, const size_t r_idx)
{
  p_c(state, r_idx);
  p_s(state);
  p_l(state);
}

}
