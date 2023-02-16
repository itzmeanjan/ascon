#pragma once
#include "hash_utils.hpp"

// Ascon Light Weight Cryptography ( i.e. AEAD, Hash and Extendable Output
// Functions ) Implementation
namespace ascon {

// Bit width of rate portion of Ascon permutation state
constexpr size_t ASCON_HASH_RATE = 64;

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ASCON_HASH_ROUND_A = 12;

// How many rounds of Ascon permutation is applied for p^b
constexpr size_t ASCON_HASH_ROUND_B = 12;

// Ascon Hash Digest Byte Length
constexpr size_t ASCON_HASH_DIGEST_LEN = 32;

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
      hash_utils::absorb<ASCON_HASH_ROUND_B>(state, msg, mlen);
      absorbed = true;
    }
  }

  // Given N -bytes input message, this routine consumes those into
  // Ascon permutation state.
  //
  // Note, this routine can be called arbitrary number of times, each time with
  // arbitrary bytes of input message, until Ascon permutation state is
  // finalized ( by calling routine with similar name ).
  //
  // This function is only enabled, when you decide to use Ascon-Hash in
  // incremental hashing mode ( compile-time decision ). By default one uses
  // Ascon-Hash API in oneshot hashing mode.
  inline void absorb(const uint8_t* const msg, const size_t mlen)
    requires(incremental)
  {
    constexpr size_t rbytes = ASCON_HASH_RATE / 8; // # -of RATE bytes

    if (!absorbed) {
      uint8_t blk_bytes[rbytes];

      const size_t blk_cnt = (offset + mlen) / rbytes;
      size_t moff = 0;

      for (size_t i = 0; i < blk_cnt; i++) {
        std::memset(blk_bytes, 0, offset);
        std::memcpy(blk_bytes + offset, msg + moff, rbytes - offset);

        const auto word = ascon_utils::from_be_bytes<uint64_t>(blk_bytes);
        state[0] ^= word;

        moff += (rbytes - offset);
        offset += (rbytes - offset);

        ascon_perm::permute<ASCON_HASH_ROUND_B>(state);
        offset %= rbytes;
      }

      const size_t rm_bytes = mlen - moff;

      std::memset(blk_bytes, 0, rbytes);
      std::memcpy(blk_bytes + offset, msg + moff, rm_bytes);

      const auto word = ascon_utils::from_be_bytes<uint64_t>(blk_bytes);
      state[0] ^= word;

      offset += rm_bytes;

      if (offset == rbytes) {
        ascon_perm::permute<ASCON_HASH_ROUND_B>(state);
        offset %= rbytes;
      }
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
  //
  // This function is only enabled, when you decide to use Ascon-Hash in
  // incremental hashing mode ( compile-time decision ). By default one uses
  // Ascon-Hash API in oneshot hashing mode.
  inline void finalize()
    requires(incremental)
  {
    constexpr size_t rbytes = ASCON_HASH_RATE / 8; // # -of RATE bytes

    if (!absorbed) {
      const size_t pad_bytes = rbytes - offset;
      const size_t pad_bits = pad_bytes * 8;
      const uint64_t pad_mask = 1ul << (pad_bits - 1);

      state[0] ^= pad_mask;

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
      constexpr auto ra = ASCON_HASH_ROUND_A;
      constexpr auto rb = ASCON_HASH_ROUND_B;
      hash_utils::squeeze<ra, rb>(state, out);

      squeezed = true;
    }
  }
};

}
