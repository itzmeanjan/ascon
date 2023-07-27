#pragma once
#include "ascon_perm.hpp"
#include "sponge.hpp"

// Ascon-PRF ( pseudo-random function )
namespace ascon_prf {

// How many rounds of Ascon permutation is applied for p^a.
constexpr size_t ROUNDS_A = 12;

// Bit width of rate portion of Ascon permutation state, during absorption.
constexpr size_t IN_RATE = 256;

// Bit width of rate portion of Ascon permutation state, during squeezing.
constexpr size_t OUT_RATE = 128;

// Byte length of secret key.
constexpr size_t KEY_LEN = 16;

// Ascon-PRF, supporting incremental message absorption and tag squeezing.
//
// Following section 2.4 and algorithm 1 of spec.
// https://eprint.iacr.org/2021/1574.pdf.
struct ascon_prf_t
{
  ascon_perm::ascon_perm_t state;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool absorbed = false;

  // Initialize 320 -bit Ascon permutation state, with a 16 -bytes secret key,
  // so that it's ready for absorbing arbitrary number of bytes.
  inline constexpr ascon_prf_t(std::span<const uint8_t, KEY_LEN> key)
  {
    ascon_auth::initialize<ROUNDS_A, IN_RATE, OUT_RATE, KEY_LEN * 8, 0u>(state, key);
    offset = 0;
    readable = 0;
    absorbed = false;
  }

  // Absorbs arbitrary number of message bytes into RATE portion of Ascon
  // permutation state. You may invoke this routine any number of times, each
  // time absorbing any number of message bytes, until the state is finalized.
  inline void absorb(std::span<const uint8_t> msg)
  {
    if (!absorbed) {
      ascon_auth::absorb<ROUNDS_A, IN_RATE>(state, offset, msg);
    }
  }

  // Finalizes 320 -bit Ascon permutation state, after absorbing arbitrary
  // number of message bytes. Once the state is finalized, it can be used for
  // squeezing tag of arbitrary bytes.
  inline void finalize()
  {
    if (!absorbed) {
      ascon_auth::finalize<ROUNDS_A, IN_RATE>(state, offset);

      absorbed = true;
      readable = OUT_RATE / 8;
    }
  }

  // Squeezes arbitrary bytes of tag, after 320 -bit Ascon permutation state is
  // finalized. You can invoke this routine any number of times, for squeezing
  // arbitrary many bytes of output.
  inline void squeeze(std::span<uint8_t> out)
  {
    if (!absorbed) {
      return;
    }

    ascon_auth::squeeze<ROUNDS_A, OUT_RATE>(state, readable, out);
  }
};

}
