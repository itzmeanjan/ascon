#include "ascon.hpp"
#include "string.h"
#include <benchmark/benchmark.h>

// 256 -bit Ascon digest
constexpr size_t DIG_LEN = 32ul;

// Fixed associated data length for Ascon AEAD scheme
constexpr size_t DATA_LEN = 64ul;

// Benchmarking Ascon permutation routine, while applying `ROUNDS` -many
// permutation round
template<const size_t ROUNDS>
static void
ascon_permutation(benchmark::State& state)
{
  static_assert(ROUNDS <= 12);

  uint64_t st[5];
  ascon_utils::random_data(st, 5);

  for (auto _ : state) {
    ascon_perm::permute<ROUNDS>(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  constexpr size_t len = sizeof(st);
  state.SetBytesProcessed(static_cast<int64_t>(len * state.iterations()));
}

// Benchmark Ascon-Hash
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/hash.hpp#L8-L27
static void
ascon_hash(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  uint8_t* msg = static_cast<uint8_t*>(malloc(mlen));
  uint8_t* digest = static_cast<uint8_t*>(malloc(DIG_LEN));

  ascon_utils::random_data(msg, mlen);
  memset(digest, 0, DIG_LEN);

  for (auto _ : state) {
    ascon::hash(msg, mlen, digest);
    benchmark::DoNotOptimize(digest);
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  free(msg);
  free(digest);
}

// Benchmark Ascon-HashA
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/hash.hpp#L29-L48
static void
ascon_hash_a(benchmark::State& state)
{
  const size_t mlen = static_cast<size_t>(state.range(0));

  uint8_t* msg = static_cast<uint8_t*>(malloc(mlen));
  uint8_t* digest = static_cast<uint8_t*>(malloc(DIG_LEN));

  ascon_utils::random_data(msg, mlen);
  memset(digest, 0, DIG_LEN);

  for (auto _ : state) {
    ascon::hash_a(msg, mlen, digest);
    benchmark::DoNotOptimize(digest);
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  free(msg);
  free(digest);
}

// Benchmark Ascon-128 authenticated encryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/auth_enc.hpp#L12-L38
static void
ascon_128_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    DoNotOptimize(encrypt_128(k, n, data, DATA_LEN, text, ct_len, enc));
    DoNotOptimize(enc);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-128 verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L8-L36
static void
ascon_128_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_128(k, n, data, DATA_LEN, enc, ct_len, dec, t));
    DoNotOptimize(dec);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
  free(dec);
}

// Benchmark Ascon-128a authenticated encryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/auth_enc.hpp#L40-L66
static void
ascon_128a_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    DoNotOptimize(encrypt_128a(k, n, data, DATA_LEN, text, ct_len, enc));
    DoNotOptimize(enc);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-128a verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L38-L66
static void
ascon_128a_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128a(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_128a(k, n, data, DATA_LEN, enc, ct_len, dec, t));
    DoNotOptimize(dec);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
  free(dec);
}

// Benchmark Ascon-80pq authenticated encryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/auth_enc.hpp#L12-L38
static void
ascon_80pq_enc(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);

  using namespace ascon;
  using namespace benchmark;

  for (auto _ : state) {
    DoNotOptimize(encrypt_80pq(k, n, data, DATA_LEN, text, ct_len, enc));
    DoNotOptimize(enc);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-80pq verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L8-L36
static void
ascon_80pq_dec(benchmark::State& state)
{
  const size_t ct_len = static_cast<size_t>(state.range(0));

  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* enc = static_cast<uint8_t*>(malloc(ct_len));
  uint8_t* dec = static_cast<uint8_t*>(malloc(ct_len));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, ct_len);

  memset(enc, 0, ct_len);
  memset(dec, 0, ct_len);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_80pq(k, n, data, DATA_LEN, text, ct_len, enc);

  for (auto _ : state) {
    DoNotOptimize(decrypt_80pq(k, n, data, DATA_LEN, enc, ct_len, dec, t));
    DoNotOptimize(dec);
  }

  const size_t per_itr = DATA_LEN + ct_len;
  state.SetBytesProcessed(static_cast<int64_t>(per_itr * state.iterations()));

  free(data);
  free(text);
  free(enc);
  free(dec);
}

// register functions for benchmarking
BENCHMARK(ascon_permutation<1>);
BENCHMARK(ascon_permutation<6>);
BENCHMARK(ascon_permutation<8>);
BENCHMARK(ascon_permutation<12>);

BENCHMARK(ascon_hash)->Arg(64);
BENCHMARK(ascon_hash)->Arg(128);
BENCHMARK(ascon_hash)->Arg(256);
BENCHMARK(ascon_hash)->Arg(512);
BENCHMARK(ascon_hash)->Arg(1024);
BENCHMARK(ascon_hash)->Arg(2048);
BENCHMARK(ascon_hash)->Arg(4096);

BENCHMARK(ascon_hash_a)->Arg(64);
BENCHMARK(ascon_hash_a)->Arg(128);
BENCHMARK(ascon_hash_a)->Arg(256);
BENCHMARK(ascon_hash_a)->Arg(512);
BENCHMARK(ascon_hash_a)->Arg(1024);
BENCHMARK(ascon_hash_a)->Arg(2048);
BENCHMARK(ascon_hash_a)->Arg(4096);

BENCHMARK(ascon_128_enc)->Arg(64);
BENCHMARK(ascon_128_enc)->Arg(128);
BENCHMARK(ascon_128_enc)->Arg(256);
BENCHMARK(ascon_128_enc)->Arg(512);
BENCHMARK(ascon_128_enc)->Arg(1024);
BENCHMARK(ascon_128_enc)->Arg(2048);
BENCHMARK(ascon_128_enc)->Arg(4096);

BENCHMARK(ascon_128_dec)->Arg(64);
BENCHMARK(ascon_128_dec)->Arg(128);
BENCHMARK(ascon_128_dec)->Arg(256);
BENCHMARK(ascon_128_dec)->Arg(512);
BENCHMARK(ascon_128_dec)->Arg(1024);
BENCHMARK(ascon_128_dec)->Arg(2048);
BENCHMARK(ascon_128_dec)->Arg(4096);

BENCHMARK(ascon_128a_enc)->Arg(64);
BENCHMARK(ascon_128a_enc)->Arg(128);
BENCHMARK(ascon_128a_enc)->Arg(256);
BENCHMARK(ascon_128a_enc)->Arg(512);
BENCHMARK(ascon_128a_enc)->Arg(1024);
BENCHMARK(ascon_128a_enc)->Arg(2048);
BENCHMARK(ascon_128a_enc)->Arg(4096);

BENCHMARK(ascon_128a_dec)->Arg(64);
BENCHMARK(ascon_128a_dec)->Arg(128);
BENCHMARK(ascon_128a_dec)->Arg(256);
BENCHMARK(ascon_128a_dec)->Arg(512);
BENCHMARK(ascon_128a_dec)->Arg(1024);
BENCHMARK(ascon_128a_dec)->Arg(2048);
BENCHMARK(ascon_128a_dec)->Arg(4096);

BENCHMARK(ascon_80pq_enc)->Arg(64);
BENCHMARK(ascon_80pq_enc)->Arg(128);
BENCHMARK(ascon_80pq_enc)->Arg(256);
BENCHMARK(ascon_80pq_enc)->Arg(512);
BENCHMARK(ascon_80pq_enc)->Arg(1024);
BENCHMARK(ascon_80pq_enc)->Arg(2048);
BENCHMARK(ascon_80pq_enc)->Arg(4096);

BENCHMARK(ascon_80pq_dec)->Arg(64);
BENCHMARK(ascon_80pq_dec)->Arg(128);
BENCHMARK(ascon_80pq_dec)->Arg(256);
BENCHMARK(ascon_80pq_dec)->Arg(512);
BENCHMARK(ascon_80pq_dec)->Arg(1024);
BENCHMARK(ascon_80pq_dec)->Arg(2048);
BENCHMARK(ascon_80pq_dec)->Arg(4096);

// main function to make this program executable
BENCHMARK_MAIN();
