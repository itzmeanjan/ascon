#include "aead/ascon128a.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>
#include <cassert>
#include <vector>

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

  auto _key = std::span<uint8_t, ascon128a_aead::KEY_LEN>(key);
  auto _nonce = std::span<uint8_t, ascon128a_aead::NONCE_LEN>(nonce);
  auto _tag = std::span<uint8_t, ascon128a_aead::TAG_LEN>(tag);
  auto _data = std::span(data);
  auto _text = std::span(text);
  auto _enc = std::span(enc);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data<uint8_t>(_nonce);
  ascon_utils::random_data(_data);
  ascon_utils::random_data(_text);

  for (auto _ : state) {
    ascon128a_aead::encrypt(_key, _nonce, _data, _text, _enc, _tag);

    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_nonce);
    benchmark::DoNotOptimize(_data);
    benchmark::DoNotOptimize(_text);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  const size_t bytes_processed = (dt_len + ct_len) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
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

  auto _key = std::span<uint8_t, ascon128a_aead::KEY_LEN>(key);
  auto _nonce = std::span<uint8_t, ascon128a_aead::NONCE_LEN>(nonce);
  auto _tag = std::span<uint8_t, ascon128a_aead::TAG_LEN>(tag);
  auto _data = std::span(data);
  auto _text = std::span(text);
  auto _enc = std::span(enc);
  auto _dec = std::span(dec);

  ascon_utils::random_data<uint8_t>(_key);
  ascon_utils::random_data<uint8_t>(_nonce);
  ascon_utils::random_data(_data);
  ascon_utils::random_data(_text);

  ascon128a_aead::encrypt(_key, _nonce, _data, _text, _enc, _tag);

  bool flag = true;
  for (auto _ : state) {
    flag &= ascon128a_aead::decrypt(_key, _nonce, _data, _enc, _dec, _tag);

    benchmark::DoNotOptimize(flag);
    benchmark::DoNotOptimize(_key);
    benchmark::DoNotOptimize(_nonce);
    benchmark::DoNotOptimize(_data);
    benchmark::DoNotOptimize(_enc);
    benchmark::DoNotOptimize(_dec);
    benchmark::DoNotOptimize(_tag);
    benchmark::ClobberMemory();
  }

  assert(flag);

  const size_t bytes_processed = (dt_len + ct_len) * state.iterations();
  state.SetBytesProcessed(bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / bytes_processed;
#endif
}

// Register for benchmarking Ascon-128a AEAD.
BENCHMARK(ascon128a_aead_encrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 4), // plain text
    { 32 }                                      // associated data
  })
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
BENCHMARK(ascon128a_aead_decrypt)
  ->ArgsProduct({
    benchmark::CreateRange(1 << 6, 1 << 12, 4), // cipher text
    { 32 }                                      // associated data
  })
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
