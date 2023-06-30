#pragma once
#include "ascon128a.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <vector>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-128a authenticated encryption with variable length input.
inline void
ascon128a_aead_encrypt(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon128a_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon128a_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon128a_aead::TAG_LEN);
  std::vector<uint8_t> data(dt_len);
  std::vector<uint8_t> text(ct_len);
  std::vector<uint8_t> enc(ct_len);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(nonce.data(), nonce.size());
  ascon_utils::random_data(data.data(), data.size());
  ascon_utils::random_data(text.data(), text.size());

  for (auto _ : state) {
    ascon128a_aead::encrypt(key.data(),
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

  const size_t bpi = key.size() + nonce.size() + dt_len + ct_len + tag.size();
  state.SetBytesProcessed(bpi * state.iterations());
}

// Benchmark Ascon-128a verified decryption with variable length input.
inline void
ascon128a_aead_decrypt(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  std::vector<uint8_t> key(ascon128a_aead::KEY_LEN);
  std::vector<uint8_t> nonce(ascon128a_aead::NONCE_LEN);
  std::vector<uint8_t> tag(ascon128a_aead::TAG_LEN);
  std::vector<uint8_t> data(dt_len);
  std::vector<uint8_t> text(ct_len);
  std::vector<uint8_t> enc(ct_len);
  std::vector<uint8_t> dec(ct_len);

  ascon_utils::random_data(key.data(), key.size());
  ascon_utils::random_data(nonce.data(), nonce.size());
  ascon_utils::random_data(data.data(), data.size());
  ascon_utils::random_data(text.data(), text.size());

  ascon128a_aead::encrypt(key.data(),
                          nonce.data(),
                          data.data(),
                          data.size(),
                          text.data(),
                          text.size(),
                          enc.data(),
                          tag.data());

  bool flag = true;
  for (auto _ : state) {
    flag &= ascon128a_aead::decrypt(key.data(),
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

  const size_t bpi = key.size() + nonce.size() + dt_len + ct_len + tag.size();
  state.SetBytesProcessed(bpi * state.iterations());
}

}
