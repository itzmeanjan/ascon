#include "ascon/ascon_perm.hpp"
#include "ascon/utils.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

// Benchmarking Ascon permutation routine, while applying `ROUNDS` -many
// permutation round.
template<const size_t ROUNDS>
void
ascon_permutation(benchmark::State& state)
  requires(ROUNDS <= ascon_perm::ASCON_PERMUTATION_MAX_ROUNDS)
{
  // Generate initial random permutation state.
  std::array<uint64_t, 5> data;
  ascon_utils::random_data<uint64_t>(data);

  ascon_perm::ascon_perm_t perm(data);

  for (auto _ : state) {
    perm.permute<ROUNDS>();

    benchmark::DoNotOptimize(perm);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = sizeof(perm) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon permutation instances.
BENCHMARK(ascon_permutation<1>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<6>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<8>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<10>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<12>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<14>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_permutation<16>)->ComputeStatistics("min", compute_min)->ComputeStatistics("max", compute_max);
