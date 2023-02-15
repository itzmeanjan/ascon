#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>

// Ascon Permutation
namespace ascon_perm {

// Maximum number of Ascon permutation rounds
constexpr size_t ROUNDS = 12;

// Ascon  permutation round constants; taken from table 4 in Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
constexpr uint64_t RC[ROUNDS]{ 0x00000000000000f0ul, 0x00000000000000e1ul,
                               0x00000000000000d2ul, 0x00000000000000c3ul,
                               0x00000000000000b4ul, 0x00000000000000a5ul,
                               0x0000000000000096ul, 0x0000000000000087ul,
                               0x0000000000000078ul, 0x0000000000000069ul,
                               0x000000000000005aul, 0x000000000000004bul };

// Addition of constants step; see section 2.6.1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
static inline constexpr void
p_c(uint64_t* const state, const size_t r_idx)
{
  state[2] ^= RC[r_idx];
}

// Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken from
// figure 5 in Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
static inline constexpr void
p_s(uint64_t* const state)
{
  state[0] ^= state[4];
  state[4] ^= state[3];
  state[2] ^= state[1];

  const uint64_t t0 = state[1] & ~state[0];
  const uint64_t t1 = state[2] & ~state[1];
  const uint64_t t2 = state[3] & ~state[2];
  const uint64_t t3 = state[4] & ~state[3];
  const uint64_t t4 = state[0] & ~state[4];

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
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
static inline constexpr void
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
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
static inline constexpr void
round(uint64_t* const state, const size_t r_idx)
{
  p_c(state, r_idx);
  p_s(state);
  p_l(state);
}

// Sequentially apply Ascon permutation round for R -many times | R <= 12;
// taken from section 2.6 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const size_t R>
static inline constexpr void
permute(uint64_t* const state)
  requires(R <= ROUNDS)
{
  constexpr size_t BEG = ROUNDS - R;

  for (size_t i = BEG; i < ROUNDS; i++) {
    round(state, i);
  }
}

}
