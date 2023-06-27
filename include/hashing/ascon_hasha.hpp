#pragma once
#include "sponge.hpp"

// Ascon-Hasha
namespace ascon_hasha {

// Bit width of rate portion of Ascon permutation state
constexpr size_t RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ROUNDS_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ROUNDS_B = 8;

// Ascon HashA Digest Byte Length
constexpr size_t DIGEST_LEN = 32;

// Ascon-HashA, supporting incremental hashing.
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
struct ascon_hasha
{
private:
  uint64_t state[5]{ 0x01470194fc6528a6,
                     0x738ec38ac0adffa7,
                     0x2ec8e3296c76384c,
                     0xd6f6a54d7f52377d,
                     0xa13c42a223be8d87 };
  size_t offset = 0;
  alignas(4) bool absorbed = false;
  alignas(4) bool squeezed = false;

public:
  // Initialization values taken from section 2.5.1 of Ascon spec.
  constexpr ascon_hasha() = default;

  // Given N -bytes input message, this routine consumes those into
  // Ascon permutation state.
  //
  // Note, this routine can be called arbitrary number of times, each time with
  // arbitrary bytes of input message, until Ascon permutation state is
  // finalized ( by calling routine with similar name ).
  //
  // This function is only enabled, when you decide to use Ascon-HashA in
  // incremental hashing mode ( compile-time decision ). By default one uses
  // Ascon-HashA API in oneshot hashing mode.
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
  // same Ascon-HashA object, doesn't do anything. After finalization, one would
  // like to read 32 -bytes of digest by squeezing sponge, which is done by
  // calling digest() function only once.
  //
  // This function is only enabled, when you decide to use Ascon-HashA in
  // incremental hashing mode ( compile-time decision ). By default one uses
  // Ascon-HashA API in oneshot hashing mode.
  inline void finalize()
  {
    if (!absorbed) {
      sponge::finalize<ROUNDS_A, RATE>(state, &offset);
      absorbed = true;
    }
  }

  // Given that N -bytes message is consumed into Ascon permutation state either
  // using single-shot hashing API or incremental hashing API ( compile-time
  // decision ), this routine can be used for squeezing out 32 -bytes message
  // digest. Once squeezed, calling this function again and again doesn't have
  // any effect.
  inline void digest(uint8_t* const out)
  {
    if (absorbed && !squeezed) {
      size_t readable = RATE / 8;
      sponge::squeeze<ROUNDS_B, RATE>(state, &readable, out, DIGEST_LEN);

      squeezed = true;
    }
  }
};

}
