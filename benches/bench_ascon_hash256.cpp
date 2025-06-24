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

  for (auto _ : state) {
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(digest);

    ascon_hash256::ascon_hash256_t hasher;
    assert(hasher.absorb(msg) == ascon_hash256::ascon_hash256_status_t::absorbed_data);
    assert(hasher.finalize() == ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
    assert(hasher.digest(digest) == ascon_hash256::ascon_hash256_status_t::message_digest_produced);

    benchmark::ClobberMemory();
  }

  const size_t total_bytes_processed = msg.size() * state.iterations();
  state.SetBytesProcessed(total_bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / total_bytes_processed;
#endif
}

BENCHMARK(bench_ascon_hash256)
  ->Name("ascon_hash256")
  ->ArgsProduct({ {
    32,
    64,
    2 * 1'024,
    16 * 1'024,
  } })
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
