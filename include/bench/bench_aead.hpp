#pragma once
#include "aead.hpp"
#include "consts.hpp"
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

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON128_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128_NONCE_LEN);
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

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));
  auto dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON128_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128_NONCE_LEN);
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

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON128A_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128A_NONCE_LEN);
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

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON128A_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));
  auto dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON128A_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON128A_NONCE_LEN);
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

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON80PQ_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON80PQ_NONCE_LEN);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    encrypt_80pq(key, nonce, data, dt_len, text, ct_len, enc, tag);

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

// Benchmark Ascon-80pq verified decryption
void
dec_80pq(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));
  const size_t dt_len = static_cast<size_t>(state.range(1));

  auto key = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_KEY_LEN));
  auto nonce = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_NONCE_LEN));
  auto tag = static_cast<uint8_t*>(std::malloc(ascon::ASCON80PQ_TAG_LEN));
  auto data = static_cast<uint8_t*>(std::malloc(dt_len));
  auto text = static_cast<uint8_t*>(std::malloc(ct_len));
  auto enc = static_cast<uint8_t*>(std::malloc(ct_len));
  auto dec = static_cast<uint8_t*>(std::malloc(ct_len));

  ascon_utils::random_data(key, ascon::ASCON80PQ_KEY_LEN);
  ascon_utils::random_data(nonce, ascon::ASCON80PQ_NONCE_LEN);
  ascon_utils::random_data(data, dt_len);
  ascon_utils::random_data(text, ct_len);

  using namespace benchmark;
  using namespace ascon;
  encrypt_80pq(key, nonce, data, dt_len, text, ct_len, enc, tag);

  for (auto _ : state) {
    bool flg = decrypt_80pq(key, nonce, data, dt_len, enc, ct_len, dec, tag);
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

}
