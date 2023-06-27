#pragma once
#include "ascon_xofa.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-XofA with variable length input and squeezed output.
inline void
ascon_xofa(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig(dlen);

  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    ascon_xofa::ascon_xofa hasher;

    hasher.absorb(msg.data(), msg.size());
    hasher.finalize();
    hasher.read(dig.data(), dig.size());

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(dig);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + dlen) * state.iterations());
}

}
