#pragma once
#include "ascon/hashes/sponge.hpp"

namespace ascon_cxof128 {

// See table 12 of Ascon standard @ https://doi.org/10.6028/NIST.SP.800-232.
static constexpr uint8_t UNIQUE_ALGORITHM_ID = 4;
static constexpr auto INITIAL_PERMUTATION_STATE = ascon_sponge_mode::compute_init_state(ascon_common_utils::compute_iv(UNIQUE_ALGORITHM_ID,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       ascon_sponge_mode::ASCON_PERM_NUM_ROUNDS,
                                                                                                                       0,
                                                                                                                       ascon_sponge_mode::RATE_BYTES));

static constexpr size_t CUSTOMIZATION_STRING_MAX_BYTE_LEN = 256;

/**
 * @brief Enumerates the possible status codes for Ascon CXOF-128 operations.
 *
 * This enum provides detailed status information returned by various functions within the
 * `ascon_cxof128_t` struct, indicating the success or specific reason for failure or
 * current state of the CXOF instance.
 */
enum class ascon_cxof128_status_t : uint8_t
{
  /// @brief Ascon-CXOF instance was successfully customized by calling `customize()` method.
  customized = 0x01,

  /// @brief Customization string length is too long, failed to customize.
  failed_to_customize_with_too_long_string,

  /// @brief Attempted to customize cXOF after it was already customized.
  already_customized,

  /// @brief The state is still in the customization phase, cXOF needs to be customized before it can absorb.
  not_yet_customized,

  /// @brief Data was successfully absorbed by the `absorb()` method.
  absorbed_data,

  /// @brief The state is still in the data absorption phase; `finalize()` must be called before squeezing output.
  still_in_data_absorption_phase,

  /// @brief The data absorption phase was successfully finalized by the `finalize()` method.
  finalized_data_absorption_phase,

  /// @brief Attempted to absorb data or finalize after the data absorption phase was already finalized.
  data_absorption_phase_already_finalized,

  /// @brief Output data was successfully squeezed by the `squeeze()` method.
  squeezed_output
};

/**
 * @brief Represents an Ascon CXOF-128 instance offering 128-bit security.
 *
 * This struct encapsulates the state of an Ascon customizable extendable output function (CXOF), providing 128-bit security. It offers
 * methods for customization, arbitrary length data absorption, finalization, and arbitrary length output squeezing.
 */
struct ascon_cxof128_t
{
private:
  ascon_perm::ascon_perm_t state = INITIAL_PERMUTATION_STATE;
  size_t offset = 0;
  size_t readable = 0;
  alignas(4) bool has_customized = false;
  alignas(4) bool finished_absorbing = false;

public:
  // Constructor(s)/ Destructor(s)
  forceinline constexpr ascon_cxof128_t() = default;
  forceinline constexpr ~ascon_cxof128_t()
  {
    state.reset();
    offset = 0;
    readable = 0;
    has_customized = false;
    finished_absorbing = false;
  }

  /**
   * @brief Customizes the CXOF with a given customization string.
   *
   * This function allows you to provide a customization string to the CXOF. The string length is limited to `CUSTOMIZATION_STRING_MAX_BYTE_LEN`.
   * The customization string is absorbed into the internal state of the CXOF. This function must be called before calling `absorb`.
   *
   * @param cust_str The customization string.
   * @return An `ascon_cxof128_status_t` indicating the success or reason for failure (e.g., `customized`, `already_customized`,
   * `failed_to_customize_with_too_long_string`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_cxof128_status_t customize(std::span<const uint8_t> cust_str)
  {
    if (has_customized) {
      return ascon_cxof128_status_t::already_customized;
    }
    if (cust_str.size() > CUSTOMIZATION_STRING_MAX_BYTE_LEN) {
      return ascon_cxof128_status_t::failed_to_customize_with_too_long_string;
    }

    const size_t cust_str_bit_len = cust_str.size() * std::numeric_limits<uint8_t>::digits;

    std::array<uint8_t, ascon_sponge_mode::RATE_BYTES> cust_str_bit_len_as_bytes{};
    ascon_common_utils::to_le_bytes(cust_str_bit_len, cust_str_bit_len_as_bytes);

    ascon_sponge_mode::absorb(state, offset, cust_str_bit_len_as_bytes);
    ascon_sponge_mode::absorb(state, offset, cust_str);
    ascon_sponge_mode::finalize(state, offset);

    has_customized = true;
    return ascon_cxof128_status_t::customized;
  }

  /**
   * @brief Absorbs data into the CXOF.
   *
   * This function absorbs input data into the internal state of the CXOF. The `customize` function must be called before calling this function. This function
   * can be called multiple times before calling `finalize`.
   *
   * @param msg The data to absorb.
   * @return An `ascon_cxof128_status_t` indicating the absorption status (e.g., `absorbed_data`, `not_yet_customized`,
   * `data_absorption_phase_already_finalized`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_cxof128_status_t absorb(std::span<const uint8_t> msg)
  {
    if (!has_customized) {
      return ascon_cxof128_status_t::not_yet_customized;
    }
    if (finished_absorbing) {
      return ascon_cxof128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::absorb(state, offset, msg);
    return ascon_cxof128_status_t::absorbed_data;
  }

  /**
   * @brief Finalizes the absorption phase of the CXOF, preparing for squeezing.
   *
   * This function marks the end of the data absorption phase. It must be called after all data has been absorbed using the `absorb` function and before any
   * calls to `squeeze`. Calling this function multiple times has no effect. Calling `finalize` before `customize` is a no-op and returns `false`.
   *
   * @return An `ascon_cxof128_status_t` indicating the finalization status (e.g., `finalized_data_absorption_phase`, `not_yet_customized`,
   * `data_absorption_phase_already_finalized`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_cxof128_status_t finalize()
  {
    if (!has_customized) {
      return ascon_cxof128_status_t::not_yet_customized;
    }
    if (finished_absorbing) {
      return ascon_cxof128_status_t::data_absorption_phase_already_finalized;
    }

    ascon_sponge_mode::finalize(state, offset);

    finished_absorbing = true;
    readable = ascon_sponge_mode::RATE_BYTES;

    return ascon_cxof128_status_t::finalized_data_absorption_phase;
  }

  /**
   * @brief Squeezes output data from the CXOF.
   *
   * This function extracts output data from the CXOF. The `finalize` function must be called before calling this function. This function can be called multiple
   * times to retrieve any number of bytes of output data.
   *
   * @param out The buffer to write the squeezed output to.
   * @return An `ascon_cxof128_status_t` indicating the squeezing status (e.g., `squeezed_output`, `not_yet_customized`, `still_in_data_absorption_phase`).
   */
  [[nodiscard]]
  forceinline constexpr ascon_cxof128_status_t squeeze(std::span<uint8_t> out)
  {
    if (!has_customized) {
      return ascon_cxof128_status_t::not_yet_customized;
    }
    if (!finished_absorbing) {
      return ascon_cxof128_status_t::still_in_data_absorption_phase;
    }

    ascon_sponge_mode::squeeze(state, readable, out);
    return ascon_cxof128_status_t::squeezed_output;
  }
};

}
