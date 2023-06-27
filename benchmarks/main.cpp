#include "aead/bench_ascon128_aead.hpp"
#include "aead/bench_ascon128a_aead.hpp"
#include "aead/bench_ascon80pq_aead.hpp"
#include "bench_permutation.hpp"
#include "hashing/bench_ascon_hash.hpp"
#include "hashing/bench_ascon_hasha.hpp"
#include "hashing/bench_ascon_xof.hpp"
#include "hashing/bench_ascon_xofa.hpp"

// register for benchmarking Ascon permutation
BENCHMARK(bench_ascon::ascon_permutation<1>);
BENCHMARK(bench_ascon::ascon_permutation<6>);
BENCHMARK(bench_ascon::ascon_permutation<8>);
BENCHMARK(bench_ascon::ascon_permutation<12>);

// register for benchmarking Ascon-128 AEAD
BENCHMARK(bench_ascon::ascon128_aead_encrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // plain text
    { 32 }                                      // associated data
  });
BENCHMARK(bench_ascon::ascon128_aead_decrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // cipher text
    { 32 }                                      // associated data
  });

// register for benchmarking Ascon-128a AEAD
BENCHMARK(bench_ascon::ascon128a_aead_encrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // plain text
    { 32 }                                      // associated data
  });
BENCHMARK(bench_ascon::ascon128a_aead_decrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // cipher text
    { 32 }                                      // associated data
  });

// register for benchmarking Ascon-80pq AEAD
BENCHMARK(bench_ascon::ascon80pq_aead_encrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // plain text
    { 32 }                                      // associated data
  });
BENCHMARK(bench_ascon::ascon80pq_aead_decrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // cipher text
    { 32 }                                      // associated data
  });

// register for benchmarking Ascon {Hash, HashA, Xof, XofA}
BENCHMARK(bench_ascon::ascon_hash)->RangeMultiplier(2)->Range(1 << 6, 1 << 12);
BENCHMARK(bench_ascon::ascon_hasha)->RangeMultiplier(2)->Range(1 << 6, 1 << 12);
BENCHMARK(bench_ascon::ascon_xof)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // input, to be absorbed
    { 32, 64 }                                  // output, to be squeezed
  });
BENCHMARK(bench_ascon::ascon_xofa)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // input, to be absorbed
    { 32, 64 }                                  // output, to be squeezed
  });

// drive benchmark execution
BENCHMARK_MAIN();