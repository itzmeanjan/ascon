#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_xof128 {

// See table 12 of Ascon draft standard @ https://doi.org/10.6028/NIST.SP.800-232.ipd.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 3;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       0,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

/// @brief Enumeration representing the status of Ascon-XOF128 operations.
enum class ascon_xof128_status_t : uint8_t
{
  /// @brief Data was successfully absorbed by the `absorb()` method.
  absorbed_data = 0x01,

  /// @brief The state is still in the data absorption phase; `finalize()` must be called before squeezing output.
  still_in_data_absorption_phase,

  /// @brief The data absorption phase was successfully finalized by the `finalize()` method.
  finalized_data_absorption_phase,

  /// @brief Attempted to absorb data or finalize after the data absorption phase was already finalized.
  data_absorption_phase_already_finalized,

  /// @brief Output data was successfully squeezed by the `squeeze()` method.
  squeezed_output,
};

/**
 * @brief Ascon-based extendable-output function (XOF) offering 128-bit security. Provides methods for absorbing arbitrary long data, finalizing the internal
 * state, and squeezing arbitrarily long output sequences.
 */
struct ascon_xof128_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool finished_absorbing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_xof128_t() = default;
  forceinline constexpr ~ascon_xof128_t()
  {
    state.reset();
    offset = 0;
    readable = 0;
    finished_absorbing = false;
  }

  forceinline constexpr ascon_xof128_t(const ascon_xof128_t&) = default;
  forceinline constexpr ascon_xof128_t(ascon_xof128_t&&) = default;
  forceinline constexpr ascon_xof128_t& operator=(const ascon_xof128_t&) = default;
  forceinline constexpr ascon_xof128_t& operator=(ascon_xof128_t&&) = default;

  /**
   * @brief Absorbs input data into the XOF's internal state. This function can be called repeatedly to absorb data in chunks before calling `finalize()`.
   * @param msg The data to absorb.
   * @return An `ascon_xof128_status_t` indicating the result of the operation.
   *   - `ascon_xof128_status_t::absorbed_data`: Data was successfully absorbed.
   *   - `ascon_xof128_status_t::data_absorption_phase_already_finalized`: Data absorption phase was already finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_xof128_status_t absorb(std::span<const uint8_t> msg)
  {
    if (finished_absorbing) {
      return ascon_xof128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::absorb(state, offset, msg);
    return ascon_xof128_status_t::absorbed_data;
  }

  /**
   * @brief Completes the absorption phase of the XOF. This function must be called after all data has been absorbed using the `absorb` method. It prepares the
   * internal state for the squeezing operation.
   * @return An `ascon_xof128_status_t` indicating the result of the operation.
   *   - `ascon_xof128_status_t::finalized_data_absorption_phase`: The XOF state was successfully finalized.
   *   - `ascon_xof128_status_t::data_absorption_phase_already_finalized`: The XOF state was already finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_xof128_status_t finalize()
  {
    if (finished_absorbing) {
      return ascon_xof128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::finalize(state, offset);

    finished_absorbing = true;
    readable = ascon_sponge_mode::RATE_BYTES;

    return ascon_xof128_status_t::finalized_data_absorption_phase;
  }

  /**
   * @brief Extracts output data from the finalized XOF. This function can be called multiple times to generate an arbitrary amount of output data.
   * The `finalize` method must be called before the first call to this function.
   * @param out The buffer to write the squeezed data to.
   * @return An `ascon_xof128_status_t` indicating the result of the operation.
   *   - `ascon_xof128_status_t::squeezed_output`: Output was successfully squeezed.
   *   - `ascon_xof128_status_t::still_in_data_absorption_phase`: XOF state is not yet finalized.
   */
  [[nodiscard]]
  forceinline constexpr ascon_xof128_status_t squeeze(std::span<uint8_t> out)
  {
    if (!finished_absorbing) {
      return ascon_xof128_status_t::still_in_data_absorption_phase;
    }

    ascon_sponge_mode::squeeze(state, readable, out);
    return ascon_xof128_status_t::squeezed_output;
  }
};

}
