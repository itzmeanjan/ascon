#pragma once
#include "ascon_hash.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-Hash with variable length input.
inline void
ascon_hash(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> dig(ascon_hash::DIGEST_LEN);

  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    ascon_hash::ascon_hash hasher;

    hasher.absorb(msg.data(), msg.size());
    hasher.finalize();
    hasher.digest(dig.data());

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(dig);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + ascon_hash::DIGEST_LEN) * state.iterations());
}

}
