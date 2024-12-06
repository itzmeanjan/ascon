#include "ascon/hashes/ascon_hash256.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

static void
bench_ascon_hash256(benchmark::State& state)
{
  const size_t msg_byte_len = static_cast<size_t>(state.range(0));

  std::vector<uint8_t> msg(msg_byte_len);
  std::array<uint8_t, ascon_hash256::DIGEST_BYTE_LEN> digest{};

  generate_random_data<uint8_t>(msg);

  bool ret_val = true;
  for (auto _ : state) {
    ascon_hash256::ascon_hash256_t hasher;

    benchmark::DoNotOptimize(ret_val);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(digest);

    ret_val &= hasher.absorb(msg);
    ret_val &= hasher.finalize();
    ret_val &= hasher.digest(digest);

    benchmark::ClobberMemory();
  }

  assert(ret_val);

  const size_t total_bytes_processed = msg.size() * state.iterations();
  state.SetBytesProcessed(total_bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / total_bytes_processed;
#endif
}

BENCHMARK(bench_ascon_hash256)
  ->Name("ascon_hash256")
  ->RangeMultiplier(8)
  ->Range(32, 16 * 1'024)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
