#pragma once
#include "hash_utils.hpp"

// Ascon Light Weight Cryptography ( i.e. AEAD, Hash and Extendable Output
// Functions ) Implementation
namespace ascon {

// Ascon Hash Function with support for both oneshot and incremental hashing
//
// See section 2.5 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
template<const bool incremental = false>
struct ascon_hash
{
private:
  uint64_t state[5]{ 0xee9398aadb67f03dul,
                     0x8bb21831c60f1002ul,
                     0xb48a92db98d5da62ul,
                     0x43189921b8f8e3e8ul,
                     0x348fa5c9d525e140ul };
  size_t absorbed_len = 0;
  size_t offset = 0;
  alignas(4) bool absorbed = false;
  alignas(4) bool squeezed = false;

public:
  // Given N -bytes message, this routine can be invoked for absorbing those
  // message bytes into Ascon permutation state. This routine can be thought of
  // single-shot hash API s.t. all input bytes are ready to be consumed at once.
  // Once they are consumed using this function, 32 -bytes digest can be read
  // using `digest` routine. One thing to remember when using this single-shot
  // hashing API is that once absorbed, calling this function again and again
  // doesn't have any effect.
  inline void hash(const uint8_t* const msg, const size_t mlen)
    requires(!incremental)
  {
    if (!absorbed) {
      ascon_hash_utils::absorb<12>(state, msg, mlen);
      absorbed = true;
    }
  }

  // Given that N -bytes message is consumed into Ascon permutation state either
  // using single-shot hashing API or incremental hashing API, this routine can
  // be used for squeezing out 32 -bytes message digest. Once squeezed, calling
  // this function again and again doesn't have any effect.
  inline void digest(uint8_t* const out)
  {
    if (absorbed && !squeezed) {
      ascon_hash_utils::squeeze<12, 12>(state, out);
      squeezed = true;
    }
  }
};

}
