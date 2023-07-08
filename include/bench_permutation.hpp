#pragma once
#include "permutation.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmarking Ascon permutation routine, while applying `ROUNDS` -many
// permutation round.
template<const size_t ROUNDS>
void
ascon_permutation(benchmark::State& state)
  requires(ROUNDS <= ascon_permutation::MAX_ROUNDS)
{
  uint64_t st[5];
  ascon_utils::random_data(st, 5);

  for (auto _ : state) {
    ascon_permutation::permute<ROUNDS>(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = sizeof(st) * state.iterations();
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
