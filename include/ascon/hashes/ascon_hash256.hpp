#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_hash256 {

static constexpr size_t DIGEST_BYTE_LEN = (ascon_perm::PERMUTATION_STATE_BITWIDTH - ascon_sponge_mode::RATE_BITS) / std::numeric_limits<uint8_t>::digits;

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 2;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       DIGEST_BYTE_LEN * 8,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

/**
 * @brief Enumerates the possible status results of Ascon-Hash256 operations.
 *
 * These status codes indicate the result of calling methods like `absorb`, `finalize`, and `digest`,
 * reflecting the current state of the hashing process (e.g., whether data was absorbed, if
 * the absorption phase is finished, or if the digest has been produced).
 */
enum class ascon_hash256_status_t : uint8_t
{
  /**
   * @brief Indicates that data was successfully absorbed into the hash state.
   *
   * Returned by the `absorb` method when input data is successfully processed.
   */
  absorbed_data = 0x01,

  /**
   * @brief Indicates that the data absorption phase is still ongoing.
   *
   * Returned by the `digest` method if called before `finalize` has been successfully called.
   */
  still_in_data_absorption_phase,

  /**
   * @brief Indicates that the data absorption phase was successfully finalized.
   *
   * Returned by the `finalize` method when the absorption phase is successfully completed for the first time.
   */
  finalized_data_absorption_phase,

  /**
   * @brief Indicates that the data absorption phase has already been finalized.
   *
   * Returned by the `absorb` or `finalize` methods if called after `finalize` has already been successfully called.
   */
  data_absorption_phase_already_finalized,

  /**
   * @brief Indicates that the message digest was successfully produced.
   *
   * Returned by the `digest` method when the final hash value is successfully computed and written to the output buffer for the first time.
   */
  message_digest_produced,

  /**
   * @brief Indicates that the message digest has already been produced.
   *
   * Returned by the `digest` method if called after the digest has already been successfully produced in a previous call.
   */
  message_digest_already_produced,
};

/**
 * @brief Represents the Ascon-Hash256 hashing algorithm.
 *
 * This struct encapsulates the state and methods for computing the Ascon-Hash256 hash of a message. It uses the Ascon permutation and a sponge construction.
 * The hash function produces a 32-byte digest.
 */
struct ascon_hash256_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  alignas(4) bool finished_absorbing = false;
  alignas(4) bool finished_squeezing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_hash256_t() = default;
  forceinline constexpr ~ascon_hash256_t()
  {
    state.reset();
    offset = 0;
    finished_absorbing = false;
    finished_squeezing = false;
  }

  forceinline constexpr ascon_hash256_t(const ascon_hash256_t&) = default;
  forceinline constexpr ascon_hash256_t(ascon_hash256_t&&) = default;
  forceinline constexpr ascon_hash256_t& operator=(const ascon_hash256_t&) = default;
  forceinline constexpr ascon_hash256_t& operator=(ascon_hash256_t&&) = default;

  /**
   * @brief Absorbs data into the hash state.
   *
   * This function absorbs the provided data into the internal state of the Ascon-Hash256 function. It uses the underlying Ascon sponge construction's absorb
   * function. This function can be called multiple times to absorb data in chunks; only after calling `finalize()` will further calls to `absorb` be ignored.
   *
   * @param msg A span of bytes representing the data to absorb.
   * @return An `ascon_hash256_status_t` indicating if data was successfully absorbed (`ascon_hash256_status_t::absorbed_data`)
   * or if the data absorption phase was already finalized (`ascon_hash256_status_t::data_absorption_phase_already_finalized`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_hash256_status_t absorb(std::span<const uint8_t> msg)
  {
    if (finished_absorbing) {
      return ascon_hash256_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::absorb(state, offset, msg);
    return ascon_hash256_status_t::absorbed_data;
  }

  /**
   * @brief Finalizes the hash computation.
   *
   * This function finalizes the hash computation by padding the message and performing the necessary final transformations within the Ascon sponge
   * construction. It must be called before calling `digest()` to obtain the final hash value. Calling this function multiple times has no effect.
   * Subsequent calls to `absorb` after calling `finalize` will be ignored.
   *
   * @return An `ascon_hash256_status_t` indicating if the data absorption phase was successfully finalized
   * (`ascon_hash256_status_t::finalized_data_absorption_phase`) or if it was already finalized
   * (`ascon_hash256_status_t::data_absorption_phase_already_finalized`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_hash256_status_t finalize()
  {
    if (finished_absorbing) {
      return ascon_hash256_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::finalize(state, offset);
    finished_absorbing = true;

    return ascon_hash256_status_t::finalized_data_absorption_phase;
  }

  /**
   * @brief Extracts the hash digest.
   *
   * This function extracts the computed hash digest from the internal state.  It must be called after `finalize()`. Only the first call after `finalize()` will
   * successfully extract and return the digest; subsequent calls will only return `false`.
   *
   * @param out A span of bytes where the resulting digest will be written.  The span must be large enough to hold a digest of `DIGEST_BYTE_LEN` bytes.
   * @return An `ascon_hash256_status_t` indicating if the message digest was successfully produced (`ascon_hash256_status_t::message_digest_produced`), if the
   * data absorption phase has not yet been finalized (`ascon_hash256_status_t::still_in_data_absorption_phase`), or if the message digest has already been
   * produced (`ascon_hash256_status_t::message_digest_already_produced`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_hash256_status_t digest(std::span<uint8_t, DIGEST_BYTE_LEN> out)
  {
    if (!finished_absorbing) {
      return ascon_hash256_status_t::still_in_data_absorption_phase;
    }
    if (finished_squeezing) {
      return ascon_hash256_status_t::message_digest_already_produced;
    }

    size_t readable = ascon_sponge_mode::RATE_BYTES;
    ascon_sponge_mode::squeeze(state, readable, out);

    finished_squeezing = true;
    return ascon_hash256_status_t::message_digest_produced;
  }
};

}
