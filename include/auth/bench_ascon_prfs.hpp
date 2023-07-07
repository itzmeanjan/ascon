#pragma once
#include "ascon_prfs.hpp"
#include <benchmark/benchmark.h>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-PRFShort based authentication scheme implementation for short
// variable length input message.
inline void
ascon_prfs_authenticate(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_prfs::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(ascon_prfs::MAX_TAG_LEN);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  for (auto _ : state) {
    using namespace ascon_prfs;
    prfs_authenticate(key.data(), msg.data(), msg.size(), tag.data());

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
}

// Benchmark Ascon-PRFShort based message authentication code verification
// algorithm implementation for short variable length input message.
inline void
ascon_prfs_verify(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_prfs::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(ascon_prfs::MAX_TAG_LEN);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(msg.data(), msg.size());

  // Authentication step.
  {
    using namespace ascon_prfs;
    prfs_authenticate(key.data(), msg.data(), msg.size(), tag.data());
  }

  bool flg = true;
  for (auto _ : state) {
    // Verification step.
    using namespace ascon_prfs;
    flg &= prfs_verify(key.data(), msg.data(), msg.size(), tag.data());

    benchmark::DoNotOptimize(flg);
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  assert(flg);

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
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
