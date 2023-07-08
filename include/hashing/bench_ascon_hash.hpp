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

}
