#pragma once
#include "ascon80pq.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

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

  state.SetBytesProcessed((dt_len + ct_len) * state.iterations());
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

  for (auto _ : state) {
    bool flag = ascon80pq_aead::decrypt(key.data(),
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

  state.SetBytesProcessed((dt_len + ct_len) * state.iterations());
}

}
