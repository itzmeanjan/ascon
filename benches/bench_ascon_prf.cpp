#include "ascon/auth/ascon_prf.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon-PRF implementation for variable length input message ( to be absorbed
// ) and output tag ( to be squeezed ).
inline void
bench_ascon_prf(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t tlen = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon_prf::KEY_LEN);
  std::vector<uint8_t> msg(mlen);
  std::vector<uint8_t> tag(tlen);

  auto _key = std::span<uint8_t, ascon_prf::KEY_LEN>(key);
  auto _msg = std::span(msg);
  auto _tag = std::span(tag);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data(_msg);

  for (auto _ : state) {
    ascon_prf::ascon_prf_t prf(_key);
    prf.absorb(_msg);
    prf.finalize();
    prf.squeeze(_tag);

    benchmark::DoNotOptimize(prf);
    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_msg);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (mlen + tlen) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon-PRF.
BENCHMARK(bench_ascon_prf)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 4), // input, to be absorbed
    { 64 }                                      // output, to be squeezed
  })
  ->Name("ascon_prf")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
