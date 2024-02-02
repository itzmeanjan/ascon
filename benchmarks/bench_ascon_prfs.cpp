#include "auth/ascon_prfs.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon-PRFShort based authentication scheme implementation for short
// variable length input message.
inline void
ascon_prfs_authenticate(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range());

  std::vector<uint8_t> key(ascon_prfs::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(ascon_prfs::MAX_TAG_LEN);

  auto _key = std::span<uint8_t, ascon_prfs::KEY_LEN>(key);
  auto _msg = std::span<uint8_t>(msg);
  auto _tag = std::span<uint8_t, ascon_prfs::MAX_TAG_LEN>(tag);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  for (auto _ : state) {
    using namespace ascon_prfs;
    prfs_authenticate(_key, _msg, _tag);

    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
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

  auto _key = std::span<uint8_t, ascon_prfs::KEY_LEN>(key);
  auto _msg = std::span<uint8_t>(msg);
  auto _tag = std::span<uint8_t, ascon_prfs::MAX_TAG_LEN>(tag);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  // Authentication step.
  {
    using namespace ascon_prfs;
    prfs_authenticate(_key, _msg, _tag);
  }

  bool flg = true;
  for (auto _ : state) {
    // Verification step.
    using namespace ascon_prfs;
    flg &= prfs_verify(_key, _msg, _tag);

    benchmark::DoNotOptimize(flg);
    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  assert(flg);

  const size_t bytes_processed = (msg.size() + tag.size()) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon-PRFShort.
BENCHMARK(ascon_prfs_authenticate)
  ->RangeMultiplier(4)
  ->Range(1, ascon_prfs::MAX_MSG_LEN) // input, to be authenticated
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(ascon_prfs_verify)
  ->RangeMultiplier(4)
  ->Range(1, ascon_prfs::MAX_MSG_LEN) // input, to be authenticated
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
