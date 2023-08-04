#pragma once
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

// Ascon Permutation
namespace ascon_perm {

// Maximum number of Ascon permutation rounds
constexpr size_t MAX_ROUNDS = 12;

// Ascon  permutation round constants; taken from table 4 in Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
constexpr uint64_t RC[MAX_ROUNDS]{ 0x00000000000000f0ul, 0x00000000000000e1ul,
                                   0x00000000000000d2ul, 0x00000000000000c3ul,
                                   0x00000000000000b4ul, 0x00000000000000a5ul,
                                   0x0000000000000096ul, 0x0000000000000087ul,
                                   0x0000000000000078ul, 0x0000000000000069ul,
                                   0x000000000000005aul, 0x000000000000004bul };

// 320 -bit Ascon permutation state, on which we can apply n (<=12) -rounds
// permutation instance.
struct ascon_perm_t
{
private:
  // 320 -bit Ascon permutation state.
  std::array<uint64_t, 5> state{};

  // Addition of constants step; see section 2.6.1 of Ascon specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
  inline constexpr void p_c(const uint64_t rc) { state[2] ^= rc; }

  // Substitution layer i.e. 5 -bit S-box S(x) applied on Ascon state; taken
  // from figure 5 in Ascon specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
  inline constexpr void p_s()
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

  // Linear diffusion layer; taken from figure 4.b in Ascon specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
  inline constexpr void p_l()
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

  // Single round of Ascon permutation; taken from section 2.6 of Ascon
  // specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
  inline constexpr void round(const uint64_t rc)
  {
    p_c(rc);
    p_s();
    p_l();
  }

public:
  // Constructors
  constexpr ascon_perm_t() = default;
  constexpr ascon_perm_t(std::array<uint64_t, 5>& words) { state = words; }
  constexpr ascon_perm_t(std::array<uint64_t, 5>&& words) { state = words; }
  constexpr ascon_perm_t(const std::array<uint64_t, 5>& words) { state = words; }
  constexpr ascon_perm_t(const std::array<uint64_t, 5>&& words) { state = words; }

  // Applies Ascon permutation round for R -many times | R <= 12; taken from
  // section 2.6 of Ascon specification
  // https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
  template<const size_t R>
  inline constexpr void permute()
    requires(R <= MAX_ROUNDS)
  {
    constexpr size_t BEG = MAX_ROUNDS - R;

    for (size_t i = BEG; i < MAX_ROUNDS; i++) {
      round(RC[i]);
    }
  }

  // Zeros Ascon permutation state, for sake of reusing same object.
  inline void reset() { std::memset(this, 0x00, sizeof(*this)); }

  // Returns reference to 64 -bit row of Ascon permutation state, given idx ∈
  // [0, 5).
  inline constexpr uint64_t& operator[](const size_t idx) { return state[idx]; }

  // Returns const reference to 64 -bit row of Ascon permutation state, given
  // idx ∈ [0, 5).
  inline constexpr const uint64_t& operator[](const size_t idx) const
  {
    return state[idx];
  }

  // Returns 320 -bit whole state of Ascon permutation.
  inline constexpr std::array<uint64_t, 5> reveal() const { return state; }
};

}
