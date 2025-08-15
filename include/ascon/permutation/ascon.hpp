#pragma once
#include "ascon/utils/force_inline.hpp"
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>

// Ascon Permutation.
namespace ascon_perm {

static constexpr size_t ASCON_PERMUTATION_MAX_ROUNDS = 16;
static constexpr size_t PERMUTATION_STATE_BITWIDTH = 320;
static constexpr size_t PERMUTATION_STATE_WORD_BITWIDTH = std::numeric_limits<uint64_t>::digits;
static constexpr size_t PERMUTATION_STATE_WORD_COUNT = PERMUTATION_STATE_BITWIDTH / PERMUTATION_STATE_WORD_BITWIDTH;

// Ascon permutation round constants; taken from table 5 in Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
static constexpr std::array<uint8_t, ASCON_PERMUTATION_MAX_ROUNDS> ASCON_PERMUTATION_ROUND_CONSTANTS{ 0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3,
                                                                                                      0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b };

// 320 -bit Ascon permutation state, on which we can apply n (<=16) -rounds permutation instance.
struct ascon_perm_t
{
private:
  // 320 -bit Ascon permutation state.
  std::array<uint64_t, PERMUTATION_STATE_WORD_COUNT> state{};
  static_assert(sizeof(state) * std::numeric_limits<uint8_t>::digits == PERMUTATION_STATE_BITWIDTH);

  // Addition of constants step; see section 3.2 of Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
  forceinline constexpr void p_c(const uint64_t rc) { state[2] ^= rc; }

  // Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken from figure 5 in Ascon specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf.
  forceinline constexpr void p_s()
  {
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];

    const uint64_t row0 = state[0] ^ (~state[1] & state[2]);
    const uint64_t row2 = state[2] ^ (~state[3] & state[4]);
    const uint64_t row4 = state[4] ^ (~state[0] & state[1]);
    const uint64_t row1 = state[1] ^ (~state[2] & state[3]);
    const uint64_t row3 = state[3] ^ (~state[4] & state[0]);

    state[1] = row1 ^ row0;
    state[3] = row3 ^ row2;
    state[0] = row0 ^ row4;
    state[4] = row4;
    state[2] = ~row2;
  }

  // Linear diffusion layer; taken from section 3.4 of Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
  forceinline constexpr void p_l()
  {
    const uint64_t row0 = state[0] ^ std::rotr(state[0], 19);
    const uint64_t row1 = state[1] ^ std::rotr(state[1], 61);
    const uint64_t row2 = state[2] ^ std::rotr(state[2], 1);
    const uint64_t row3 = state[3] ^ std::rotr(state[3], 10);
    const uint64_t row4 = state[4] ^ std::rotr(state[4], 7);

    state[0] = row0 ^ std::rotr(state[0], 28);
    state[1] = row1 ^ std::rotr(state[1], 39);
    state[2] = row2 ^ std::rotr(state[2], 6);
    state[3] = row3 ^ std::rotr(state[3], 17);
    state[4] = row4 ^ std::rotr(state[4], 41);
  }

  // Single round of Ascon permutation; taken from section 3 of Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
  forceinline constexpr void round(const uint64_t rc)
  {
    p_c(rc);
    p_s();
    p_l();
  }

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_perm_t() = default;
  forceinline constexpr ~ascon_perm_t() { reset(); }

  forceinline constexpr ascon_perm_t(std::array<uint64_t, 5>& words) { state = words; }
  forceinline constexpr ascon_perm_t(std::array<uint64_t, 5>&& words) { state = words; }
  forceinline constexpr ascon_perm_t(const std::array<uint64_t, 5>& words) { state = words; }
  forceinline constexpr ascon_perm_t(const std::array<uint64_t, 5>&& words) { state = words; }

  // Accessor(s)
  [[nodiscard]]
  forceinline constexpr uint64_t& operator[](const size_t idx)
  {
    return state[idx];
  }
  [[nodiscard]]
  forceinline constexpr const uint64_t& operator[](const size_t idx) const
  {
    return state[idx];
  }

  [[nodiscard]]
  forceinline constexpr std::array<uint64_t, 5> reveal() const
  {
    return state;
  }
  forceinline constexpr void reset() { state.fill(0); }

  // Applies Ascon permutation round for R -many times | R <= 16; taken from section 3 of Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
  template<const size_t R>
  forceinline constexpr void permute()
    requires(R <= ASCON_PERMUTATION_MAX_ROUNDS)
  {
    constexpr size_t BEG = ASCON_PERMUTATION_MAX_ROUNDS - R;

    if constexpr (R % 2 == 0) {
      for (size_t i = BEG; i < ASCON_PERMUTATION_MAX_ROUNDS; i += 2) {
        round(ASCON_PERMUTATION_ROUND_CONSTANTS[i]);
        round(ASCON_PERMUTATION_ROUND_CONSTANTS[i + 1]);
      }
    } else {
      for (size_t i = BEG; i < ASCON_PERMUTATION_MAX_ROUNDS; i++) {
        round(ASCON_PERMUTATION_ROUND_CONSTANTS[i]);
      }
    }
  }
};

}
