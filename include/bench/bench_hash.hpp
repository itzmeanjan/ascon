#pragma once
#include "hash.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-Hash on target CPU
void
hash(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  constexpr size_t dlen = ascon::ASCON_HASH_DIGEST_LEN;

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto digest = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  for (auto _ : state) {
    ascon::ascon_hash hasher;
    hasher.hash(msg, mlen);
    hasher.digest(digest);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(digest);
    benchmark::DoNotOptimize(msg);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + dlen) * state.iterations());

  std::free(msg);
  std::free(digest);
}

// Benchmark Ascon-HashA on target CPU
void
hasha(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  constexpr size_t dlen = ascon::ASCON_HASH_DIGEST_LEN;

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto digest = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  for (auto _ : state) {
    ascon::ascon_hasha hasher;
    hasher.hash(msg, mlen);
    hasher.digest(digest);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(digest);
    benchmark::DoNotOptimize(msg);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + dlen) * state.iterations());

  std::free(msg);
  std::free(digest);
}

// Benchmark Ascon-XOF on target CPU
void
xof(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = static_cast<size_t>(state.range(1));

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto digest = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  for (auto _ : state) {
    ascon::ascon_xof hasher;
    hasher.hash(msg, mlen);
    hasher.read(digest, dlen);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(digest);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + dlen) * state.iterations());

  std::free(msg);
  std::free(digest);
}

// Benchmark Ascon-XOFA on target CPU
void
xofa(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));
  const size_t dlen = static_cast<size_t>(state.range(1));

  auto msg = static_cast<uint8_t*>(std::malloc(mlen));
  auto digest = static_cast<uint8_t*>(std::malloc(dlen));

  ascon_utils::random_data(msg, mlen);

  for (auto _ : state) {
    ascon::ascon_xofa hasher;
    hasher.hash(msg, mlen);
    hasher.read(digest, dlen);

    benchmark::DoNotOptimize(hasher);
    benchmark::DoNotOptimize(msg);
    benchmark::DoNotOptimize(digest);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed((mlen + dlen) * state.iterations());

  std::free(msg);
  std::free(digest);
}

}
