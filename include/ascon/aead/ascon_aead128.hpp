#pragma once
#include "ascon/aead/mode.hpp"
#include "ascon/utils/force_inline.hpp"

namespace ascon_aead128 {

static constexpr size_t KEY_BYTE_LEN = ascon_aead_mode::KEY_BYTE_LEN;
static constexpr size_t NONCE_BYTE_LEN = ascon_aead_mode::NONCE_BYTE_LEN;
static constexpr size_t TAG_BYTE_LEN = ascon_aead_mode::TAG_BYTE_LEN;

// Given a 16 -bytes key, a 16 -bytes nonce, an arbitrary length associated data and an arbitrary length plain text,
// this routine encrypts plain text, producing equal length cipher text. It also produces a 16 -bytes authentication tag,
// which authenticates both associated data and cipher text.
//
// Note, associated data doesn't ever get encrypted, it only gets authenticated.
forceinline void
encrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> plaintext,
        std::span<uint8_t> ciphertext,
        std::span<uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};

  ascon_aead_mode::initialize(state, key, nonce);
  ascon_aead_mode::process_associated_data(state, associated_data);
  ascon_aead_mode::process_plaintext(state, plaintext, ciphertext);
  ascon_aead_mode::finalize(state, key, tag);
}

// Given a 16 -bytes key, a 16 -bytes nonce, a 16 -bytes authentication tag, an arbitrary length associated data and
// an arbitrary length cipher text, this routine decrypts cipher text, producing equal length plain text, while also checking
// authenticity of both cipher text and associated data, using 16 -bytes tag.
//
// It returns truth value, only when authentication passes, otherwise it returns false, while also zeroing out plain text.
forceinline bool
decrypt(std::span<const uint8_t, KEY_BYTE_LEN> key,
        std::span<const uint8_t, NONCE_BYTE_LEN> nonce,
        std::span<const uint8_t> associated_data,
        std::span<const uint8_t> cipher,
        std::span<uint8_t> text,
        std::span<const uint8_t, TAG_BYTE_LEN> tag)
{
  ascon_perm::ascon_perm_t state{};
  std::array<uint8_t, TAG_BYTE_LEN> computed_tag{};

  ascon_aead_mode::initialize(state, key, nonce);
  ascon_aead_mode::process_associated_data(state, associated_data);
  ascon_aead_mode::process_ciphertext(state, cipher, text);
  ascon_aead_mode::finalize(state, key, computed_tag);

  const uint32_t flg = ascon_utils::ct_eq_byte_array<TAG_BYTE_LEN>(tag, computed_tag);
  ascon_utils::ct_conditional_memset(~flg, text, 0);

  return static_cast<bool>(flg);
}

}
