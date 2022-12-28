#include "bench/bench_ascon.hpp"

// register functions for benchmarking Ascon permutation
BENCHMARK(bench_ascon::permutation<1>);
BENCHMARK(bench_ascon::permutation<6>);
BENCHMARK(bench_ascon::permutation<8>);
BENCHMARK(bench_ascon::permutation<12>);

// register functions for benchmarking Ascon {Hash, HashA}
BENCHMARK(bench_ascon::hash)->Arg(64);
BENCHMARK(bench_ascon::hash_a)->Arg(64);
BENCHMARK(bench_ascon::hash)->Arg(128);
BENCHMARK(bench_ascon::hash_a)->Arg(128);
BENCHMARK(bench_ascon::hash)->Arg(256);
BENCHMARK(bench_ascon::hash_a)->Arg(256);
BENCHMARK(bench_ascon::hash)->Arg(512);
BENCHMARK(bench_ascon::hash_a)->Arg(512);
BENCHMARK(bench_ascon::hash)->Arg(1024);
BENCHMARK(bench_ascon::hash_a)->Arg(1024);
BENCHMARK(bench_ascon::hash)->Arg(2048);
BENCHMARK(bench_ascon::hash_a)->Arg(2048);
BENCHMARK(bench_ascon::hash)->Arg(4096);
BENCHMARK(bench_ascon::hash_a)->Arg(4096);

// register functions for benchmarking Ascon-128 AEAD
BENCHMARK(bench_ascon::enc_128)->Arg(64);
BENCHMARK(bench_ascon::dec_128)->Arg(64);
BENCHMARK(bench_ascon::enc_128)->Arg(128);
BENCHMARK(bench_ascon::dec_128)->Arg(128);
BENCHMARK(bench_ascon::enc_128)->Arg(256);
BENCHMARK(bench_ascon::dec_128)->Arg(256);
BENCHMARK(bench_ascon::enc_128)->Arg(512);
BENCHMARK(bench_ascon::dec_128)->Arg(512);
BENCHMARK(bench_ascon::enc_128)->Arg(1024);
BENCHMARK(bench_ascon::dec_128)->Arg(1024);
BENCHMARK(bench_ascon::enc_128)->Arg(2048);
BENCHMARK(bench_ascon::dec_128)->Arg(2048);
BENCHMARK(bench_ascon::enc_128)->Arg(4096);
BENCHMARK(bench_ascon::dec_128)->Arg(4096);

// register functions for benchmarking Ascon-128a AEAD
BENCHMARK(bench_ascon::enc_128a)->Arg(64);
BENCHMARK(bench_ascon::dec_128a)->Arg(64);
BENCHMARK(bench_ascon::enc_128a)->Arg(128);
BENCHMARK(bench_ascon::dec_128a)->Arg(128);
BENCHMARK(bench_ascon::enc_128a)->Arg(256);
BENCHMARK(bench_ascon::dec_128a)->Arg(256);
BENCHMARK(bench_ascon::enc_128a)->Arg(512);
BENCHMARK(bench_ascon::dec_128a)->Arg(512);
BENCHMARK(bench_ascon::enc_128a)->Arg(1024);
BENCHMARK(bench_ascon::dec_128a)->Arg(1024);
BENCHMARK(bench_ascon::enc_128a)->Arg(2048);
BENCHMARK(bench_ascon::dec_128a)->Arg(2048);
BENCHMARK(bench_ascon::enc_128a)->Arg(4096);
BENCHMARK(bench_ascon::dec_128a)->Arg(4096);

// register functions for benchmarking Ascon-80pq AEAD
BENCHMARK(bench_ascon::enc_80pq)->Arg(64);
BENCHMARK(bench_ascon::dec_80pq)->Arg(64);
BENCHMARK(bench_ascon::enc_80pq)->Arg(128);
BENCHMARK(bench_ascon::dec_80pq)->Arg(128);
BENCHMARK(bench_ascon::enc_80pq)->Arg(256);
BENCHMARK(bench_ascon::dec_80pq)->Arg(256);
BENCHMARK(bench_ascon::enc_80pq)->Arg(512);
BENCHMARK(bench_ascon::dec_80pq)->Arg(512);
BENCHMARK(bench_ascon::enc_80pq)->Arg(1024);
BENCHMARK(bench_ascon::dec_80pq)->Arg(1024);
BENCHMARK(bench_ascon::enc_80pq)->Arg(2048);
BENCHMARK(bench_ascon::dec_80pq)->Arg(2048);
BENCHMARK(bench_ascon::enc_80pq)->Arg(4096);
BENCHMARK(bench_ascon::dec_80pq)->Arg(4096);

// drive benchmark execution
BENCHMARK_MAIN();
