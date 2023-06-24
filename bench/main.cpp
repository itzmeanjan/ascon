#include "bench/bench_ascon.hpp"

// register functions for benchmarking Ascon permutation
BENCHMARK(bench_ascon::permutation<1>);
BENCHMARK(bench_ascon::permutation<6>);
BENCHMARK(bench_ascon::permutation<8>);
BENCHMARK(bench_ascon::permutation<12>);

// register functions for benchmarking Ascon-128 AEAD
BENCHMARK(bench_ascon::enc_128)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });
BENCHMARK(bench_ascon::dec_128)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });

// register functions for benchmarking Ascon-128a AEAD
BENCHMARK(bench_ascon::enc_128a)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });
BENCHMARK(bench_ascon::dec_128a)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });

// register functions for benchmarking Ascon-80pq AEAD
BENCHMARK(bench_ascon::enc_80pq)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });
BENCHMARK(bench_ascon::dec_80pq)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32 } });

// register functions for benchmarking Ascon {Hash, HashA, Xof, XofA}
BENCHMARK(bench_ascon::hash)->RangeMultiplier(2)->Range(1 << 6, 1 << 12);
BENCHMARK(bench_ascon::hasha)->RangeMultiplier(2)->Range(1 << 6, 1 << 12);
BENCHMARK(bench_ascon::xof)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32, 64 } });
BENCHMARK(bench_ascon::xofa)
  ->ArgsProduct({ benchmark::CreateRange(1 << 6, 1 << 12, 2), { 32, 64 } });

// drive benchmark execution
BENCHMARK_MAIN();
