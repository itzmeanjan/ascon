#include "bench_helper.hpp"
#include "hashing/ascon_xof.hpp"
#include <benchmark/benchmark.h>
#include <span>
#include <vector>

// Benchmark Ascon-Xof with variable length input and squeezed output.
inline void
bench_ascon_xof(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig(dlen);

  auto _msg = std::span(msg);
  auto _dig = std::span(dig);

  ascon_utils::random_data(_msg);

  for (auto _ : state) {
    ascon_xof::ascon_xof_t hasher;

    hasher.absorb(_msg);
    hasher.finalize();
    hasher.squeeze(_dig);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_dig);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (mlen + dlen) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon-Xof.
BENCHMARK(bench_ascon_xof)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // input, to be absorbed
    { 32, 64 }                                  // output, to be squeezed
  })
  ->Name("ascon_xof")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
