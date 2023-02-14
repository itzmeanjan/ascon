#pragma once
#include "aead.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

// Benchmark Ascon Light Weight Cryptography Implementation
namespace bench_ascon {

// Benchmark Ascon-128 authenticated encryption
void
enc_128(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    encrypt_128(key, nonce, data, dt_len, text, ct_len, enc, tag);

    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(text);
    DoNotOptimize(ct_len);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(tag);
}

// Benchmark Ascon-128 verified decryption
void
dec_128(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace benchmark;
  using namespace ascon;
  encrypt_128(key, nonce, data, dt_len, text, ct_len, enc, tag);

  for (auto _ : state) {
    bool flg = decrypt_128(key, nonce, data, dt_len, enc, ct_len, dec, tag);
    DoNotOptimize(flg);
    assert(flg);

    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(ct_len);
    DoNotOptimize(dec);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
  std::free(tag);
}

// Benchmark Ascon-128a authenticated encryption
void
enc_128a(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    encrypt_128a(key, nonce, data, dt_len, text, ct_len, enc, tag);

    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(text);
    DoNotOptimize(ct_len);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(tag);
}

// Benchmark Ascon-128a verified decryption
void
dec_128a(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t* key = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(16));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(16));

  ascon_utils::random_data(key, 16);
  ascon_utils::random_data(nonce, 16);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace benchmark;
  using namespace ascon;
  encrypt_128a(key, nonce, data, dt_len, text, ct_len, enc, tag);

  for (auto _ : state) {
    bool flg = decrypt_128a(key, nonce, data, dt_len, enc, ct_len, dec, tag);
    DoNotOptimize(flg);
    assert(flg);

    DoNotOptimize(key);
    DoNotOptimize(nonce);
    DoNotOptimize(data);
    DoNotOptimize(dt_len);
    DoNotOptimize(enc);
    DoNotOptimize(ct_len);
    DoNotOptimize(dec);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(key);
  std::free(nonce);
  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
  std::free(tag);
}

// Benchmark Ascon-80pq authenticated encryption
void
enc_80pq(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    const auto tag = encrypt_80pq(k, n, data, dt_len, text, ct_len, enc);

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(text);
    DoNotOptimize(enc);
    DoNotOptimize(tag);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
}

// Benchmark Ascon-80pq verified decryption
void
dec_80pq(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(std::malloc(dt_len));
  uint8_t* text = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  std::memset(enc, 0, ct_len);
  std::memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_80pq(k, n, data, dt_len, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_80pq(k, n, data, dt_len, enc, ct_len, dec, t));

    DoNotOptimize(k);
    DoNotOptimize(n);
    DoNotOptimize(data);
    DoNotOptimize(enc);
    DoNotOptimize(dec);
    DoNotOptimize(t);
    ClobberMemory();
  }

  const size_t per_itr = dt_len + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  std::free(data);
  std::free(text);
  std::free(enc);
  std::free(dec);
}

}
