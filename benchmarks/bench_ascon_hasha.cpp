#include "hashing/ascon_hasha.hpp"
#include <benchmark/benchmark.h>
#include <span>
#include <vector>

// Benchmark Ascon-HashA with variable length input.
inline void
bench_ascon_hasha(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig(ascon_hasha::DIGEST_LEN);

  auto _msg = std::span(msg);
  auto _dig = std::span<uint8_t, ascon_hasha::DIGEST_LEN>(dig);

  ascon_utils::random_data(_msg);

  for (auto _ : state) {
    ascon_hasha::ascon_hasha_t hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.digest(_dig);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_dig);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (msg.size() + dig.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
}

// Register for benchmarking Ascon-HashA.
BENCHMARK(bench_ascon_hasha)
  ->RangeMultiplier(2)
  ->Range(1 << 6, 1 << 12)
  ->Name("ascon_hasha");
