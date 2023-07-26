#pragma once
#include "ascon_perm.hpp"
#include "sponge.hpp"

// Ascon-XofA
namespace ascon_xofa {

// Bit width of rate portion of Ascon permutation state
constexpr size_t RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ROUNDS_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ROUNDS_B = 8;

// 64 -bit initialization value, obtained from section 2.5.1 of spec.
constexpr uint64_t IV = 0x00400c0400000000ul;

// Compile-time computed initial permutation state used in Ascon-XofA.
constexpr auto INIT_PERM_STATE = sponge::compute_init_state(IV);

// Ascon-XofA ( extendable output function ), supporting incremental hashing.
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
struct ascon_xofa
{
private:
  ascon_perm::ascon_perm_t state = INIT_PERM_STATE;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool absorbed = false;

public:
  // Constructor
  constexpr inline ascon_xofa() = default;

  // Given N -bytes input message, this routine consumes those into Ascon
  // permutation state.
  //
  // Note, this routine can be called arbitrary number of times, each time with
  // arbitrary bytes of input message, until Ascon permutation state is
  // finalized ( by calling routine with similar name ).
  inline void absorb(std::span<const uint8_t> msg)
  {
    if (!absorbed) {
      sponge::absorb<ROUNDS_B, RATE>(state, offset, msg);
    }
  }

  // After consuming N -many bytes ( by invoking absorb routine arbitrary many
  // times, each time with arbitrary input bytes ), this routine is invoked when
  // no more input bytes remaining to be consumed by Ascon permutation state.
  //
  // Note, once this routine is called, calling absorb() or finalize() again, on
  // same Ascon-XOFA object, doesn't do anything. After finalization, one would
  // like to read arbitrary many bytes of digest by squeezing sponge, which is
  // done by calling squeeze() function as many times required.
  inline void finalize()
  {
    if (!absorbed) {
      sponge::finalize<ROUNDS_A, RATE>(state, offset);

      absorbed = true;
      readable = RATE / 8;
    }
  }

  // Given that N -bytes input message is already absorbed into Ascon permutation state,
  // this routine is used for squeezing M -bytes out of consumable part of state ( i.e.
  // rate portion of state ).
  //
  // This routine can be used for squeezing arbitrary number of bytes from Ascon
  // permutation state.
  //
  // Make sure you absorb message bytes first, then only call this function, otherwise
  // it can't squeeze out anything. Once done with squeezing, you can reuse same hasher
  // object for another absorb->finalize->squeeze round, by explicitly calling reset()
  // function.
  inline void squeeze(std::span<uint8_t> out)
  {
    if (!absorbed) {
      return;
    }

    sponge::squeeze<ROUNDS_B, RATE>(state, readable, out);
  }

  // Resets internal state of Ascon-XofA object, making it ready for yet another
  // absorb->finalize->squeeze round. You must explicitly call this function if you're
  // interested in reusing the same object for absorbing new messages.
  inline void reset()
  {
    std::memset(this, 0x00, sizeof(*this));
    this->state = INIT_PERM_STATE;
  }
};

}
