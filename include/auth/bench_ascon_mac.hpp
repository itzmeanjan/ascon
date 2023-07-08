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

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
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

  const size_t bytes_per_iter = mlen + 2 * ascon_mac::TAG_LEN;
  const size_t bytes_processed = bytes_per_iter * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
}

}
