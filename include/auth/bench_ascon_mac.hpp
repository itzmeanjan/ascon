#pragma once
#include "ascon_mac.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-MAC authentication implementation for variable length input
// message.
inline void
ascon_mac_authenticate(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(ascon_mac::TAG_LEN);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    ascon_mac::ascon_mac mac(key.data());

    mac.authenticate(msg.data(), msg.size());
    mac.finalize(tag.data());

    benchmark::DoNotOptimize(mac);
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_per_iter = key.size() + msg.size() + tag.size();
  state.SetBytesProcessed(bytes_per_iter * state.iterations());
}

// Benchmark Ascon-MAC verification implementation for variable length input
// message.
inline void
ascon_mac_verify(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> transmitted_tag(ascon_mac::TAG_LEN);
  std::vector<uint8_t> computed_tag(ascon_mac::TAG_LEN);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  // Authentication step.
  {
    ascon_mac::ascon_mac mac(key.data());

    mac.authenticate(msg.data(), msg.size());
    mac.finalize(transmitted_tag.data());
  }

  for (auto _ : state) {
    // Verification step.
    ascon_mac::ascon_mac mac(key.data());

    mac.authenticate(msg.data(), msg.size());
    mac.finalize(computed_tag.data());
    mac.verify(transmitted_tag.data(), computed_tag.data());

    benchmark::DoNotOptimize(mac);
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(transmitted_tag);
    benchmark::DoNotOptimize(computed_tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_per_iter = key.size() + mlen + 2 * ascon_mac::TAG_LEN;
  state.SetBytesProcessed(bytes_per_iter * state.iterations());
}

}
