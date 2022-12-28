#pragma once
#include "ascon.hpp"
#include <benchmark/benchmark.h>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Fixed associated data length for Ascon AEAD scheme
constexpr size_t DATA_LEN = 64ul;

// Benchmark Ascon-128 authenticated encryption
void
ascon_128_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    const auto tag = encrypt_128(k, n, data, DATA_LEN, text, ct_len, enc);

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(text);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
}

// Benchmark Ascon-128 verified decryption
void
ascon_128_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);
  std::memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_128(k, n, data, DATA_LEN, enc, ct_len, dec, t));

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(t);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
}

// Benchmark Ascon-128a authenticated encryption
void
ascon_128a_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    const auto tag = encrypt_128a(k, n, data, DATA_LEN, text, ct_len, enc);

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(text);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
}

// Benchmark Ascon-128a verified decryption
void
ascon_128a_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);
  std::memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128a(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_128a(k, n, data, DATA_LEN, enc, ct_len, dec, t));

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(t);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
}

// Benchmark Ascon-80pq authenticated encryption
void
ascon_80pq_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    const auto tag = encrypt_80pq(k, n, data, DATA_LEN, text, ct_len, enc);

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(text);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
}

// Benchmark Ascon-80pq verified decryption
void
ascon_80pq_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);
  std::memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_80pq(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_80pq(k, n, data, DATA_LEN, enc, ct_len, dec, t));

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(t);
    ClobberMemory();
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
}

}
