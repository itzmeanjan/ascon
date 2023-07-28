#pragma once
#include "ascon_perm.hpp"
#include "sponge.hpp"

// Ascon-MAC ( message authentication code )
namespace ascon_mac {

// How many rounds of Ascon permutation is applied for p^a
constexpr size_t ROUNDS_A = 12;

// Bit width of rate portion of Ascon permutation state, during absorption
constexpr size_t IN_RATE = 256;

// Bit width of rate portion of Ascon permutation state, during squeezing
constexpr size_t OUT_RATE = 128;

// Byte length of secret key.
constexpr size_t KEY_LEN = 16;

// Byte length of authentication tag.
constexpr size_t TAG_LEN = 16;

// Ascon-MAC, with support for incremental message authentication.
//
// Following section 2.5 and algorithm 2 of spec.
// https://eprint.iacr.org/2021/1574.pdf.
struct ascon_mac_t
{
private:
  ascon_perm::ascon_perm_t state;
  size_t offset = 0;
  alignas(8) bool absorbed = false;

public:
  // Initialize 320 -bit Ascon permutation state, with 16 -bytes secret key, so
  // that we can start authenticating arbitrary many message bytes.
  inline constexpr ascon_mac_t(std::span<const uint8_t, KEY_LEN> key)
  {
    ascon_auth::initialize<ROUNDS_A, IN_RATE, OUT_RATE, KEY_LEN * 8, TAG_LEN * 8>(state,
                                                                                  key);

    offset = 0;
    absorbed = false;
  }

  // Absorbs arbitrary many message bytes into RATE portion of Ascon permutation
  // state, for authenticating it. You may invoke this routine any number of
  // times, each time absorbing any number of message bytes, for authentication
  // purpose, until state is finalized, producing 16 -bytes tag/ mac.
  inline void authenticate(std::span<const uint8_t> msg)
  {
    if (!absorbed) {
      ascon_auth::absorb<ROUNDS_A, IN_RATE>(state, offset, msg);
    }
  }

  // Given that arbitrary many message bytes are already absorbed into Ascon
  // permutation state, for authentication purpose, this routine can be used for
  // finalizing the state, so that we can squeeze 16 -bytes authentication tag/
  // message authentication code, from it.
  inline void finalize(std::span<uint8_t, TAG_LEN> tag)
  {
    if (!absorbed) {
      ascon_auth::finalize<ROUNDS_A, IN_RATE>(state, offset);

      absorbed = true;
      size_t readable = OUT_RATE / 8;

      ascon_auth::squeeze<ROUNDS_A, OUT_RATE>(state, readable, tag);
    }
  }

  // For verifying the received ( say over the wire ) authentication tag, one compares
  // it with the locally computed tag, in constant-time. This routine returns boolean
  // truth value, denoting success or false value, denoting failure, during tag
  // verification.
  //
  // Note, the Ascon-MAC instance used for verifying tag, must have locally computed
  // tag, by invoking authenticate->finalize routines, as required.
  inline bool verify(std::span<const uint8_t, TAG_LEN> transmitted_tag, // received
                     std::span<const uint8_t, TAG_LEN> finalized_tag    // computed
  )
  {
    bool fl = false;
    fl = ascon_utils::ct_eq_byte_array(transmitted_tag, finalized_tag);
    return fl & absorbed;
  }
};

}
