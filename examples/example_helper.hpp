#pragma once
#include <iomanip>
#include <random>
#include <span>
#include <sstream>

// Generate `len` -many random sampled data of type T | T = unsigned integer.
//
// **Not cryptographically secure !**
template<typename T>
inline void
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

// Converts byte array into hex string; see https://stackoverflow.com/a/14051107.
inline const std::string
bytes_to_hex_string(std::span<const uint8_t> bytes)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < bytes.size(); i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }
  return ss.str();
}
