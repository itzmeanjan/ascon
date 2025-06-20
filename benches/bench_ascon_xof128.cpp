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

  for (auto _ : state) {
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(output);

    ascon_xof128::ascon_xof128_t hasher;
    assert(hasher.absorb(msg) == ascon_xof128::ascon_xof128_status_t::absorbed_data);
    assert(hasher.finalize() == ascon_xof128::ascon_xof128_status_t::finalized_data_absorption_phase);
    assert(hasher.squeeze(output) == ascon_xof128::ascon_xof128_status_t::squeezed_output);

    benchmark::ClobberMemory();
  }

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
