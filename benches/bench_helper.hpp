#pragma once
#include <algorithm>
#include <random>
#include <span>
#include <vector>

const auto compute_min = [](const std::vector<double>& v) -> double { return *std::min_element(v.begin(), v.end()); };
const auto compute_max = [](const std::vector<double>& v) -> double { return *std::max_element(v.begin(), v.end()); };

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
