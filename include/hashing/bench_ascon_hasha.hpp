#pragma once
#include "ascon_hasha.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-HashA with variable length input.
inline void
ascon_hasha(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig(ascon_hasha::DIGEST_LEN);

  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    ascon_hasha::ascon_hasha hasher;

    hasher.absorb(msg.data(), msg.size());
    hasher.finalize();
    hasher.digest(dig.data());

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(dig);
    benchmark::ClobberMemory();
  }

  const size_t bytes_per_iter = msg.size() + dig.size();
  state.SetBytesProcessed(bytes_per_iter * state.iterations());
}

}
