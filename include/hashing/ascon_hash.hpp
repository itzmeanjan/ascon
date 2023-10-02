#pragma once
#include "ascon_perm.hpp"
#include "sponge.hpp"

// Ascon-Hash
namespace ascon_hash {

// Bit width of rate portion of Ascon permutation state
constexpr size_t RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ROUNDS_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ROUNDS_B = 12;

// Ascon-Hash Digest Byte Length
constexpr size_t DIGEST_LEN = sizeof(ascon_perm::ascon_perm_t) - (RATE / 8);

// 64 -bit initialization value, obtained from section 2.5.1 of spec.
constexpr uint64_t IV = 0x00400c0000000100ul;

// Compile-time computed initial permutation state used in Ascon-Hash.
constexpr auto INIT_PERM_STATE = sponge::compute_init_state(IV);

// Ascon-Hash, supporting incremental hashing.
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
struct ascon_hash_t
{
private:
  ascon_perm::ascon_perm_t state = INIT_PERM_STATE;
  size_t offset = 0;
  alignas(4) bool absorbed = false;
  alignas(4) bool squeezed = false;

public:
  // Constructor
  inline constexpr ascon_hash_t() = default;

  // Given N -bytes input message, this routine consumes those into
  // Ascon permutation state.
  //
  // Note, this routine can be called arbitrary number of times, each time with
  // arbitrary bytes of input message, until Ascon permutation state is
  // finalized ( by calling routine with similar name ).
  inline constexpr void absorb(std::span<const uint8_t> msg)
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
  // same Ascon-Hash object, doesn't do anything. After finalization, one would
  // like to read 32 -bytes of digest by squeezing sponge, which is done by
  // calling digest() function only once.
  inline void constexpr finalize()
  {
    if (!absorbed) {
      sponge::finalize<ROUNDS_A, RATE>(state, offset);
      absorbed = true;
    }
  }

  // Given that N -bytes message is consumed into Ascon permutation state, this routine
  // can be used for squeezing out 32 -bytes message digest. Once squeezed, calling this
  // function again and again doesn't have any effect. You may continue using same
  // hasher object for another round of absorb->finalize->digest flow, by explicitly
  // calling reset() function.
  inline void constexpr digest(std::span<uint8_t, DIGEST_LEN> out)
  {
    if (absorbed && !squeezed) {
      size_t readable = RATE / 8;
      sponge::squeeze<ROUNDS_B, RATE>(state, readable, out);

      squeezed = true;
    }
  }

  // Resets internal state of Ascon-Hash object, making it ready for yet another
  // absorb->finalize->digest round. You must explicitly call this function if you're
  // interested in reusing the same object for absorbing new messages.
  inline void constexpr reset()
  {
    this->state = INIT_PERM_STATE;
    this->offset = 0;
    this->absorbed = false;
    this->squeezed = false;
  }
};

}
