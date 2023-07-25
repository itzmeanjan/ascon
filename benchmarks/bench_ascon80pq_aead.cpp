#pragma once
#include "aead/ascon80pq.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <vector>

// Benchmark Ascon-80pq authenticated encryption with variable length input.
inline void
ascon80pq_aead_encrypt(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon80pq_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon80pq_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon80pq_aead::TAG_LEN);
  std::vector<uint8_t> data(dt_len);
  std::vector<uint8_t> text(ct_len);
  std::vector<uint8_t> enc(ct_len);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(nonce.data(), nonce.size());
  ascon_utils::random_data(data.data(), data.size());
  ascon_utils::random_data(text.data(), text.size());

  for (auto _ : state) {
    ascon80pq_aead::encrypt(key.data(),
                            nonce.data(),
                            data.data(),
                            data.size(),
                            text.data(),
                            text.size(),
                            enc.data(),
                            tag.data());

    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(text);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (dt_len + ct_len) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
}

// Benchmark Ascon-80pq verified decryption with variable length input.
inline void
ascon80pq_aead_decrypt(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon80pq_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon80pq_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon80pq_aead::TAG_LEN);
  std::vector<uint8_t> data(dt_len);
  std::vector<uint8_t> text(ct_len);
  std::vector<uint8_t> enc(ct_len);
  std::vector<uint8_t> dec(ct_len);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(nonce.data(), nonce.size());
  ascon_utils::random_data(data.data(), data.size());
  ascon_utils::random_data(text.data(), text.size());

  ascon80pq_aead::encrypt(key.data(),
                          nonce.data(),
                          data.data(),
                          data.size(),
                          text.data(),
                          text.size(),
                          enc.data(),
                          tag.data());

  bool flag = true;
  for (auto _ : state) {
    flag &= ascon80pq_aead::decrypt(key.data(),
                                    nonce.data(),
                                    data.data(),
                                    data.size(),
                                    enc.data(),
                                    enc.size(),
                                    dec.data(),
                                    tag.data());

    benchmark::DoNotOptimize(flag);
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(dec);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  assert(flag);

  const size_t bytes_processed = (dt_len + ct_len) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif

#ifdef INSTRUCTIONS_PER_CYCLE
  const double ipc = state.counters["INSTRUCTIONS"] / state.counters["CYCLES"];
  state.counters["INSTRUCTIONS/ CYCLE"] = ipc;
#endif
}

// Register for benchmarking Ascon-80pq AEAD.
BENCHMARK(ascon80pq_aead_encrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // plain text
    { 32 }                                      // associated data
  });
BENCHMARK(ascon80pq_aead_decrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 2), // cipher text
    { 32 }                                      // associated data
  });