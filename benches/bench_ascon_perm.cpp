#include "ascon/permutation/ascon.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

template<const size_t ROUNDS>
static void
ascon_permutation(benchmark::State& state)
  requires(ROUNDS <= ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS)
{
  std::array<uint64_t, 5> state_words{};
  generate_random_data<uint64_t>(state_words);

  ascon_perm::ascon_perm_t perm_state(state_words);

  for (auto _ : state) {
    benchmark::DoNotOptimize(perm_state);
    perm_state.permute<ROUNDS>();
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = sizeof(perm_state) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

BENCHMARK(ascon_permutation<1>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<8>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<12>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<16>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
