#pragma once
#include "hash.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// 256 -bit Ascon digest
constexpr size_t DIG_LEN = 32ul;

// Benchmark Ascon-Hash on target CPU
void
ascon_hash(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* digest = static_cast<uint8_t*>(std::malloc(DIG_LEN));

  ascon_utils::random_data(msg, mlen);
  memset(digest, 0, DIG_LEN);

  for (auto _ : state) {
    ascon::hash(msg, mlen, digest);

    benchmark::DoNotOptimize(digest);
    benchmark::DoNotOptimize(msg);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(digest);
}

// Benchmark Ascon-HashA on target CPU
void
ascon_hash_a(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* digest = static_cast<uint8_t*>(std::malloc(DIG_LEN));

  ascon_utils::random_data(msg, mlen);
  memset(digest, 0, DIG_LEN);

  for (auto _ : state) {
    ascon::hash_a(msg, mlen, digest);

    benchmark::DoNotOptimize(digest);
    benchmark::DoNotOptimize(msg);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(digest);
}

}
