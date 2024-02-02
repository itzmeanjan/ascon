#include "ascon_perm.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmarking Ascon permutation routine, while applying `ROUNDS` -many
// permutation round.
template<const size_t ROUNDS>
void
ascon_permutation(benchmark::State& state)
  requires(ROUNDS <= ascon_perm::MAX_ROUNDS)
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
BENCHMARK(ascon_permutation<1>);
BENCHMARK(ascon_permutation<6>);
BENCHMARK(ascon_permutation<8>);
BENCHMARK(ascon_permutation<12>);
