#include "ascon/aead/ascon_aead128.hpp"
#include "bench_helper.hpp"
#include <benchmark/benchmark.h>

static void
ascon_aead128_encrypt(benchmark::State& state)
{
  const size_t associated_data_len = static_cast<size_t>(state.range(0));
  const size_t plain_text_len = static_cast<size_t>(state.range(1));

  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key{};
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};
  std::vector<uint8_t> associated_data(associated_data_len);
  std::vector<uint8_t> plaintext(plain_text_len);
  std::vector<uint8_t> ciphertext(plain_text_len);

  generate_random_data<uint8_t>(key);
  generate_random_data<uint8_t>(nonce);
  generate_random_data<uint8_t>(associated_data);
  generate_random_data<uint8_t>(plaintext);

  for (auto _ : state) {
    benchmark::DoNotOptimize(key);
    benchmark::DoNotOptimize(nonce);
    benchmark::DoNotOptimize(associated_data);
    benchmark::DoNotOptimize(plaintext);
    benchmark::DoNotOptimize(ciphertext);
    benchmark::DoNotOptimize(tag);

    ascon_aead128::encrypt(key, nonce, associated_data, plaintext, ciphertext, tag);

    benchmark::ClobberMemory();
  }

  const size_t total_bytes_processed = (associated_data_len + plain_text_len) * state.iterations();
  state.SetBytesProcessed(total_bytes_processed);

#ifdef CYCLES_PER_BYTE
  state.counters["CYCLES/ BYTE"] = state.counters["CYCLES"] / total_bytes_processed;
#endif
}

BENCHMARK(ascon_aead128_encrypt)
  ->ArgsProduct({
    { 32 },                     // Associated data
    { 32, 256, 2'048, 16'384 }, // Plain text
  })
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
