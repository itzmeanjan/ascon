#pragma once
#include "ascon_prf.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-PRF implementation for variable length input message ( to be
// absorbed ) and output tag ( to be squeezed ).
inline void
ascon_prf(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t tlen = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon_prf::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(tlen);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    ascon_prf::ascon_prf prf(key.data());

    prf.absorb(msg.data(), msg.size());
    prf.finalize();
    prf.squeeze(tag.data(), tag.size());

    benchmark::DoNotOptimize(prf);
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (mlen + tlen) * state.iterations();
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
