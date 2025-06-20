#include "ascon/hashes/ascon_xof128.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

static void
bench_ascon_xof128(benchmark::State& state)
{
  const size_t msg_byte_len = static_cast<size_t>(state.range(0));
  const size_t out_byte_len = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> msg(msg_byte_len);
  std::vector<uint8_t> output(out_byte_len);

  generate_random_data<uint8_t>(msg);

  bool ret_val = true;
  for (auto _ : state) {
    ascon_xof128::ascon_xof128_t hasher;

    benchmark::DoNotOptimize(ret_val);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(output);

    ret_val &= hasher.absorb(msg);
    ret_val &= hasher.finalize();
    ret_val &= hasher.squeeze(output);

    benchmark::ClobberMemory();
  }

  assert(ret_val);

  const size_t total_bytes_processed = (msg_byte_len + out_byte_len) * state.iterations();
  state.SetBytesProcessed(total_bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / total_bytes_processed;
#endif
}

BENCHMARK(bench_ascon_xof128)
  ->Name("ascon_xof128")
  ->ArgsProduct({
    { 32, 64, 2 * 1'048, 16 * 1'024 }, // Input, to be absorbed
    { 64, 512 }                        // Output, to be squeezed
  })
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
