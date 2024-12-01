#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>

static constexpr size_t MIN_AD_LEN = 0;
static constexpr size_t MAX_AD_LEN = 64;

static constexpr size_t MIN_PT_LEN = 0;
static constexpr size_t MAX_PT_LEN = 128;

static constexpr size_t MIN_MSG_LEN = 0;
static constexpr size_t MAX_MSG_LEN = 256;

static constexpr size_t MIN_OUT_LEN = 0;
static constexpr size_t MAX_OUT_LEN = 256;

enum class aead_mutation_kind_t : uint8_t
{
  mutate_key,
  mutate_nonce,
  mutate_tag,
  mutate_associated_data,
  mutate_cipher_text,
};

// Generate `len` -many random sampled data of type T | T = unsigned integer.
//
// **Not cryptographically secure !**
template<typename T>
static void
generate_random_data(std::span<T> data)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<> dis;

  for (size_t i = 0; i < data.size(); i++) {
    data[i] = dis(gen);
  }
}

constexpr void
do_bitflip(std::span<uint8_t> msg)
{
  const size_t target_byte_idx = msg.size() - 1;
  const size_t target_bit_idx = 3;

  const auto hi_bit_mask = static_cast<uint8_t>(0xffu << (target_bit_idx + 1));
  const auto lo_bit_mask = static_cast<uint8_t>(0xffu >> (std::numeric_limits<uint8_t>::digits - target_bit_idx));

  const uint8_t selected_byte = msg[target_byte_idx];
  const uint8_t selected_bit = (selected_byte >> target_bit_idx) & 0b1u;
  const uint8_t selected_bit_flipped = (~selected_bit) & 0b1;

  msg[target_byte_idx] = (selected_byte & hi_bit_mask) ^ (selected_bit_flipped << target_bit_idx) ^ (selected_byte & lo_bit_mask);
}

// Given a byte array of length L, this routine can be used for interpreting those bytes as a hex-encoded string of length 2*L.
template<size_t L>
constexpr std::array<char, L * 2>
bytes_to_hex(std::array<uint8_t, L> bytes)
{
  constexpr std::array<char, 16> table{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  std::array<char, bytes.size() * 2> hex{};

  for (size_t i = 0; i < bytes.size(); i++) {
    hex[2 * i + 0] = table[bytes[i] >> 4];
    hex[2 * i + 1] = table[bytes[i] & 0x0f];
  }

  return hex;
}
