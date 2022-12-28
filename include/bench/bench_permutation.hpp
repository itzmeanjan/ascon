#pragma once
#include "permutation.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmarking Ascon permutation routine, while applying `ROUNDS` -many
// permutation round
template<const size_t ROUNDS>
void
ascon_permutation(benchmark::State& state)
{
  static_assert(ROUNDS <= 12);

  uint64_t st[5];
  ascon_utils::random_data(st, 5);

  for (auto _ : state) {
    ascon_perm::permute<ROUNDS>(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  constexpr size_t len = sizeof(st);
  state.SetBytesProcessed(static_cast<int64_t>(len * state.iterations()));
}

}
