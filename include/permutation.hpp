#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

// Ascon Permutation
namespace ascon_perm {

// Maximum number of Ascon permutation rounds
constexpr size_t ROUNDS = 12;

// Ascon  permutation round constants; taken from table 4 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
constexpr uint64_t RC[ROUNDS] = { 0x00000000000000f0ul, 0x00000000000000e1ul,
                                  0x00000000000000d2ul, 0x00000000000000c3ul,
                                  0x00000000000000b4ul, 0x00000000000000a5ul,
                                  0x0000000000000096ul, 0x0000000000000087ul,
                                  0x0000000000000078ul, 0x0000000000000069ul,
                                  0x000000000000005aul, 0x000000000000004bul };

// Addition of constants step; see section 2.6.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
inline static void
p_c(uint64_t* const state, const size_t r_idx)
{
  state[2] ^= RC[r_idx];
}

// Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken from
// figure 5 in Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
inline static void
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
inline static void
p_l(uint64_t* const state)
{
  using namespace std;

  state[0] = state[0] ^ rotr(state[0], 19) ^ rotr(state[0], 28);
  state[1] = state[1] ^ rotr(state[1], 61) ^ rotr(state[1], 39);
  state[2] = state[2] ^ rotr(state[2], 1) ^ rotr(state[2], 6);
  state[3] = state[3] ^ rotr(state[3], 10) ^ rotr(state[3], 17);
  state[4] = state[4] ^ rotr(state[4], 7) ^ rotr(state[4], 41);
}

// Single round of Ascon permutation; taken from section 2.6 of Ascon
// specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
inline static void
round(uint64_t* const state, const size_t r_idx)
{
  p_c(state, r_idx);
  p_s(state);
  p_l(state);
}

// Compile time check to ensure template argument of `permute(...)` is <= 12
inline static constexpr bool
check_lte12(const size_t a)
{
  return a <= 12;
}

// Sequentially apply Ascon permutation round for R -many times | R <= 12;
// taken from section 2.6 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
template<const size_t R>
inline static void
permute(uint64_t* const state) requires(check_lte12(R))
{
  constexpr size_t BEG = ROUNDS - R;

  for (size_t i = BEG; i < ROUNDS; i++) {
    round(state, i);
  }
}

}
