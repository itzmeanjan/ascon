#include "auth/ascon_mac.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon-MAC authentication implementation for variable length input message.
inline void
ascon_mac_authenticate(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(ascon_mac::TAG_LEN);

  auto _key = std::span<uint8_t, ascon_mac::KEY_LEN>(key);
  auto _msg = std::span<uint8_t>(msg);
  auto _tag = std::span<uint8_t, ascon_mac::TAG_LEN>(tag);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  for (auto _ : state) {
    ascon_mac::ascon_mac_t mac(_key);
    mac.authenticate(_msg);
    mac.finalize(_tag);

    benchmark::DoNotOptimize(mac);
    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Benchmark Ascon-MAC verification implementation for variable length input message.
inline void
ascon_mac_verify(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_mac::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> transmitted_tag(ascon_mac::TAG_LEN);
  std::vector<uint8_t> computed_tag(ascon_mac::TAG_LEN);

  auto _key = std::span<uint8_t, ascon_mac::KEY_LEN>(key);
  auto _msg = std::span<uint8_t>(msg);
  auto _transmitted_tag = std::span<uint8_t, ascon_mac::TAG_LEN>(transmitted_tag);
  auto _computed_tag = std::span<uint8_t, ascon_mac::TAG_LEN>(computed_tag);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  // Authentication step.
  {
    ascon_mac::ascon_mac_t mac(_key);
    mac.authenticate(_msg);
    mac.finalize(_transmitted_tag);
  }

  bool flag = true;
  for (auto _ : state) {
    // Verification step.
    ascon_mac::ascon_mac_t mac(_key);
    mac.authenticate(_msg);
    mac.finalize(_computed_tag);
    flag &= mac.verify(_transmitted_tag, _computed_tag);

    benchmark::DoNotOptimize(mac);
    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_transmitted_tag);
    benchmark::DoNotOptimize(_computed_tag);
    benchmark::DoNotOptimize(flag);
    benchmark::ClobberMemory();
  }

  assert(flag);

  const size_t bytes_per_iter = mlen + 2 * ascon_mac::TAG_LEN;
  const size_t bytes_processed = bytes_per_iter * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon-MAC.
BENCHMARK(ascon_mac_authenticate)
  ->RangeMultiplier(2)
  ->Range(1 << 6, 1 << 12) // input, to be authenticated
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_mac_verify)
  ->RangeMultiplier(2)
  ->Range(1 << 6, 1 << 12) // input, to be authenticated
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
