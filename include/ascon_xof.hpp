#pragma once
#include "hash_utils.hpp"

// Ascon Light Weight Cryptography ( i.e. AEAD, Hash and Extendable Output
// Functions ) Implementation
namespace ascon {

// Bit width of rate portion of Ascon permutation state
constexpr size_t ASCON_XOF_RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ASCON_XOF_ROUND_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ASCON_XOF_ROUND_B = 12;

// Ascon XOF Function with support for both oneshot and incremental hashing
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const bool incremental = false>
struct ascon_xof
{
private:
  uint64_t state[5]{ 0xb57e273b814cd416,
                     0x2b51042562ae2420,
                     0x66a3a7768ddf2218,
                     0x5aad0a7a8153650c,
                     0x4f3e0e32539493b6 };
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool absorbed = false;

public:
  // Given N -bytes message, this routine can be invoked for absorbing those
  // message bytes into Ascon permutation state. This routine can be thought of
  // single-shot hash API s.t. all input bytes are ready to be consumed at once.
  // Once they are consumed using this function, arbitrary many digest bytes can
  // be read using `read` function. One thing to remember when using this
  // single-shot hashing API is that once absorbed, calling this function again
  // and again doesn't have any side effect.
  inline void hash(const uint8_t* const msg, const size_t mlen)
    requires(!incremental)
  {
    if (!absorbed) {
      ascon_hash_utils::absorb<ASCON_XOF_ROUND_B>(state, msg, mlen);
      absorbed = true;

      ascon_perm::permute<ASCON_XOF_ROUND_A>(state);
      readable = ASCON_XOF_RATE / 8;
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

    constexpr size_t rbytes = ASCON_XOF_RATE / 8;

    size_t ooff = 0;
    while (ooff < olen) {
      const size_t elen = std::min(readable, olen - ooff);
      const size_t soff = rbytes - readable;

      uint64_t word = state[0];

      if constexpr (std::endian::native == std::endian::little) {
        word = ascon_utils::bswap(word);
      }

      std::memcpy(out + ooff, reinterpret_cast<uint8_t*>(&word) + soff, elen);

      readable -= elen;
      ooff += elen;

      if (readable == 0) {
        ascon_perm::permute<ASCON_XOF_ROUND_B>(state);
        readable = ASCON_XOF_RATE / 8;
      }
    }
  }
};

}
