#pragma once
#include "ascon/aead/duplex.hpp"
#include "ascon/permutation/ascon.hpp"
#include "ascon/utils/common.hpp"
#include "ascon/utils/force_inline.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

namespace ascon_aead128 {

static constexpr size_t KEY_BYTE_LEN = ascon_duplex_mode::KEY_BYTE_LEN;
static constexpr size_t NONCE_BYTE_LEN = ascon_duplex_mode::NONCE_BYTE_LEN;
static constexpr size_t TAG_BYTE_LEN = ascon_duplex_mode::TAG_BYTE_LEN;

/**
 * @brief Represents the status of an Ascon-AEAD128 operation.
 *
 * This enum provides detailed information about the current state of the Ascon-AEAD128
 * encryption or decryption process, including the absorption of associated data,
 * encryption/decryption of plaintext/ciphertext, and finalization steps.
 */
enum class ascon_aead128_status_t : uint8_t
{
  /// @brief Indicates that data has been successfully absorbed into the Ascon state.
  absorbed_data = 0x01,

  /// @brief Indicates that the process is still in the data absorption phase.
  still_in_data_absorption_phase,

  /// @brief Indicates that the data absorption phase has been successfully finalized.
  finalized_data_absorption_phase,

  /// @brief Indicates that the data absorption phase has already been finalized.
  data_absorption_phase_already_finalized,

  /// @brief Indicates that plaintext has been successfully encrypted, generating ciphertext.
  encrypted_plaintext,

  /// @brief Indicates that the encryption phase has been successfully completed.
  finalized_encryption_phase,

  /// @brief Indicates that the encryption phase has already been finalized.
  encryption_phase_already_finalized,

  /// @brief Indicates that ciphertext has been successfully decrypted, generating plaintext.
  decrypted_ciphertext,

  /// @brief Indicates that decryption was successful and the computed tag matches the provided tag.
  decryption_success_as_tag_matches,

  /// @brief Indicates that decryption failed due to a tag mismatch.
  decryption_failure_due_to_tag_mismatch,

  /// @brief Indicates that the decryption phase has already been finalized.
  decryption_phase_already_finalized,
};

/**
 * @brief Provides an incremental API for the Ascon-AEAD128 authenticated encryption with associated data algorithm.
 *
 * This struct allows for encryption and decryption with associated data in a step-by-step manner.
 * It encapsulates the state of the Ascon-AEAD128 algorithm, managing the key, internal state, and
 * flags for tracking the progress of the encryption/decryption process.
 */
struct ascon_aead128_t
{
private:
  std::array<uint8_t, KEY_BYTE_LEN> key{};

  ascon_perm::ascon_perm_t state{};
  size_t offset = 0;
  size_t total_absorbed_data_byte_len = 0;

  alignas(4) bool finished_absorbing_data = false;
  alignas(4) bool finished_encrypting_plaintext = false;
  alignas(8) bool finished_decrypting_ciphertext = false;

public:
  /**
   * @brief Constructs an `ascon_aead128_t` object, initializing the Ascon state with the key and nonce.
   *
   * @param key The 128-bit encryption key.
   * @param nonce The 128-bit nonce (must be unique for each encryption with the same key).
   */
  forceinline constexpr ascon_aead128_t(std::span<const uint8_t, KEY_BYTE_LEN> key, std::span<const uint8_t, NONCE_BYTE_LEN> nonce)
  {
    std::copy(key.begin(), key.end(), this->key.begin());
    ascon_duplex_mode::initialize(state, this->key, nonce);
  }

  /**
   * @brief Destroys the `ascon_aead128_t` object and resets its internal state, zeroing the key.
   */
  forceinline constexpr ~ascon_aead128_t() { this->reset(); }

  /**
   * @brief Absorbs associated data into the Ascon state.
   *
   * This function can be called multiple times to absorb associated data in chunks. It must be called
   * before `encrypt_plaintext` or `decrypt_ciphertext`.
   *
   * @param data A span of bytes representing the associated data.
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `absorbed_data`: Data was successfully absorbed.
   *   - `data_absorption_phase_already_finalized`: Data absorption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t absorb_data(std::span<const uint8_t> data)
  {
    if (finished_absorbing_data) {
      return ascon_aead128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_duplex_mode::absorb_associated_data(state, offset, data);
    total_absorbed_data_byte_len += data.size();

    return ascon_aead128_status_t::absorbed_data;
  }

  /**
   * @brief Finalizes the absorption of associated data.
   *
   * This function must be called after all associated data has been absorbed and before calling
   * `encrypt_plaintext` or `decrypt_ciphertext`.
   *
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `finalized_data_absorption_phase`: Data absorption phase was successfully finalized.
   *   - `data_absorption_phase_already_finalized`: Data absorption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t finalize_data()
  {
    if (finished_absorbing_data) {
      return ascon_aead128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_duplex_mode::finalize_associated_data(state, offset, total_absorbed_data_byte_len);
    finished_absorbing_data = true;

    return ascon_aead128_status_t::finalized_data_absorption_phase;
  }

  /**
   * @brief Encrypts plaintext and produces ciphertext.
   *
   * This function can be called multiple times to encrypt plaintext in chunks.  It must be called after
   * `finalize_data` and before `finalize_encrypt`.
   *
   * @param plaintext A span of bytes representing the plaintext to be encrypted.
   * @param ciphertext A span of bytes where the resulting ciphertext will be written. Must be the same
   *        length as the plaintext.
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `encrypted_plaintext`: Plaintext was successfully encrypted.
   *   - `still_in_data_absorption_phase`:  Data absorption phase has not yet been finalized.
   *   - `encryption_phase_already_finalized`: Encryption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t encrypt_plaintext(std::span<const uint8_t> plaintext, std::span<uint8_t> ciphertext)
  {
    if (!finished_absorbing_data) {
      return ascon_aead128_status_t::still_in_data_absorption_phase;
    }
    if (finished_encrypting_plaintext) {
      return ascon_aead128_status_t::encryption_phase_already_finalized;
    }

    ascon_duplex_mode::encrypt_plaintext(state, offset, plaintext, ciphertext);
    return ascon_aead128_status_t::encrypted_plaintext;
  }

  /**
   * @brief Finalizes the encryption process and generates the authentication tag.
   *
   * This function must be called after all plaintext has been encrypted using `encrypt_plaintext`.
   *
   * @param tag A span of bytes where the resulting authentication tag will be written.  Must be of length
   *        `TAG_BYTE_LEN`.
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `finalized_encryption_phase`: Encryption phase was successfully finalized and the tag was generated.
   *   - `still_in_data_absorption_phase`: Data absorption phase has not yet been finalized.
   *   - `encryption_phase_already_finalized`: Encryption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t finalize_encrypt(std::span<uint8_t, TAG_BYTE_LEN> tag)
  {
    if (!finished_absorbing_data) {
      return ascon_aead128_status_t::still_in_data_absorption_phase;
    }
    if (finished_encrypting_plaintext) {
      return ascon_aead128_status_t::encryption_phase_already_finalized;
    }

    ascon_duplex_mode::finalize_ciphering(state, offset);
    finished_encrypting_plaintext = true;
    ascon_duplex_mode::finalize(state, key, tag);

    this->key.fill(0);
    this->state.reset();

    return ascon_aead128_status_t::finalized_encryption_phase;
  }

  /**
   * @brief Decrypts ciphertext and produces plaintext.
   *
   * This function can be called multiple times to decrypt ciphertext in chunks. It must be called after
   * `finalize_data` and before `finalize_decrypt`.
   *
   * @param ciphertext A span of bytes representing the ciphertext to be decrypted.
   * @param plaintext A span of bytes where the resulting plaintext will be written. Must be the same length
   *        as the ciphertext.
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `decrypted_ciphertext`: Ciphertext was successfully decrypted.
   *   - `still_in_data_absorption_phase`: Data absorption phase has not yet been finalized.
   *   - `decryption_phase_already_finalized`: Decryption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t decrypt_ciphertext(std::span<const uint8_t> ciphertext, std::span<uint8_t> plaintext)
  {
    if (!finished_absorbing_data) {
      return ascon_aead128_status_t::still_in_data_absorption_phase;
    }
    if (finished_decrypting_ciphertext) {
      return ascon_aead128_status_t::decryption_phase_already_finalized;
    }

    ascon_duplex_mode::decrypt_ciphertext(state, offset, ciphertext, plaintext);
    return ascon_aead128_status_t::decrypted_ciphertext;
  }

  /**
   * @brief Finalizes the decryption process and verifies the authentication tag.
   *
   * This function must be called after all ciphertext has been decrypted using `decrypt_ciphertext`.
   *
   * @param tag A span of bytes representing the authentication tag to be verified. Must be of length
   *        `TAG_BYTE_LEN`.
   * @return An `ascon_aead128_status_t` indicating the status of the operation:
   *   - `decryption_success_as_tag_matches`: Decryption was successful and the tag matched.
   *   - `decryption_failure_due_to_tag_mismatch`: Decryption failed because the tag did not match. Discard all of previously decrypted plaintext.
   *   - `still_in_data_absorption_phase`: Data absorption phase has not yet been finalized.
   *   - `decryption_phase_already_finalized`: Decryption phase has already been finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_aead128_status_t finalize_decrypt(std::span<const uint8_t, TAG_BYTE_LEN> tag)
  {
    if (!finished_absorbing_data) {
      return ascon_aead128_status_t::still_in_data_absorption_phase;
    }
    if (finished_decrypting_ciphertext) {
      return ascon_aead128_status_t::decryption_phase_already_finalized;
    }

    ascon_duplex_mode::finalize_ciphering(state, offset);
    finished_decrypting_ciphertext = true;

    std::array<uint8_t, TAG_BYTE_LEN> computed_tag{};

    ascon_duplex_mode::finalize(state, key, computed_tag);
    const uint32_t flag = ascon_common_utils::ct_eq_byte_array<TAG_BYTE_LEN>(tag, computed_tag);

    this->key.fill(0);
    this->state.reset();

    return flag == std::numeric_limits<uint32_t>::max() ? ascon_aead128_status_t::decryption_success_as_tag_matches
                                                        : ascon_aead128_status_t::decryption_failure_due_to_tag_mismatch;
  }

private:
  /**
   * @brief Resets the internal state of the `ascon_aead128_t` object, zeroing the key and flags.
   *
   * This function is called when object destructor is triggered.
   */
  forceinline constexpr void reset()
  {
    this->key.fill(0);

    this->state.reset();
    this->offset = 0;
    this->total_absorbed_data_byte_len = 0;

    this->finished_absorbing_data = false;
    this->finished_encrypting_plaintext = false;
    this->finished_decrypting_ciphertext = false;
  }
};

}
