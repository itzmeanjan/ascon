#pragma once
#include "sponge.hpp"

// Ascon-XofA
namespace ascon_xofa {

// Bit width of rate portion of Ascon permutation state
constexpr size_t RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ROUNDS_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ROUNDS_B = 8;

// Ascon-XofA ( extendable output function ), supporting incremental hashing.
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
struct ascon_xofa
{
private:
  uint64_t state[5]{ 0x44906568b77b9832,
                     0xcd8d6cae53455532,
                     0xf7b5212756422129,
                     0x246885e1de0d225b,
                     0xa8cb5ce33449973f };
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool absorbed = false;

public:
  // Initialization values taken from section 2.5.1 of Ascon spec.
  constexpr ascon_xofa() = default;

  // Given N -bytes input message, this routine consumes those into Ascon
  // permutation state.
  //
  // Note, this routine can be called arbitrary number of times, each time with
  // arbitrary bytes of input message, until Ascon permutation state is
  // finalized ( by calling routine with similar name ).
  inline void absorb(const uint8_t* const msg, const size_t mlen)
  {
    if (!absorbed) {
      sponge::absorb<ROUNDS_B, RATE>(state, &offset, msg, mlen);
    }
  }

  // After consuming N -many bytes ( by invoking absorb routine arbitrary many
  // times, each time with arbitrary input bytes ), this routine is invoked when
  // no more input bytes remaining to be consumed by Ascon permutation state.
  //
  // Note, once this routine is called, calling absorb() or finalize() again, on
  // same Ascon-XOFA object, doesn't do anything. After finalization, one would
  // like to read arbitrary many bytes of digest by squeezing sponge, which is
  // done by calling `read()` function as many times required.
  inline void finalize()
  {
    if (!absorbed) {
      sponge::finalize<ROUNDS_A, RATE>(state, &offset);

      absorbed = true;
      readable = RATE / 8;
    }
  }

  // Given that N -bytes input message is already absorbed into Ascon
  // permutation state using `hash( ... )`/ `absorb(...)` & `finalize(...)`
  // routine, this routine is used for squeezing M -bytes out of consumable part
  // of state ( i.e. rate portion of state ).
  //
  // This routine can be used for squeezing arbitrary number of bytes from Ascon
  // permutation state.
  //
  // Make sure you absorb message bytes first, then only call this function,
  // otherwise it can't squeeze out anything.
  inline void read(uint8_t* const out, const size_t olen)
  {
    if (!absorbed) {
      return;
    }

    sponge::squeeze<ROUNDS_B, RATE>(state, &readable, out, olen);
  }
};

}
