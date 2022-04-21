#include "ascon.hpp"
#include "string.h"
#include <benchmark/benchmark.h>

// --- Feel free to play with following macro values ---

#ifndef MSG_LEN
#define MSG_LEN 4096ul // bytes; >= 0
#endif

#define DIG_LEN 32ul          // bytes; == 32
static_assert(DIG_LEN == 32); // 256 -bit Ascon digest

// plain text and ciphered data must be of same length
#if !(defined TEXT_LEN) && (defined CIPHER_LEN)
#define TEXT_LEN CIPHER_LEN // bytes
#elif (defined TEXT_LEN) && !(defined CIPHER_LEN)
#define CIPHER_LEN TEXT_LEN // bytes
#else
#define TEXT_LEN 4096ul   // bytes; >= 0
#define CIPHER_LEN 4096ul // bytes; >= 0
#endif

static_assert(TEXT_LEN == CIPHER_LEN);

// associated data length for AEAD
// read https://en.wikipedia.org/wiki/Authenticated_encryption
#ifndef DATA_LEN
#define DATA_LEN 64ul // bytes; >= 0
#endif

// --- --- ---

// Benchmark Ascon-Hash
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/hash.hpp#L8-L27
static void
ascon_hash(benchmark::State& state)
{
  uint8_t* msg = static_cast<uint8_t*>(malloc(MSG_LEN));
  uint8_t* digest = static_cast<uint8_t*>(malloc(DIG_LEN));

  ascon_utils::random_data(msg, MSG_LEN);
  memset(digest, 0, DIG_LEN);

  size_t itr = 0;
  for (auto _ : state) {
    ascon::hash(msg, MSG_LEN, digest);

    benchmark::DoNotOptimize(digest);
    memset(digest, 0, DIG_LEN);
    benchmark::DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>(MSG_LEN * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(msg);
  free(digest);
}

// Benchmark Ascon-HashA
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/hash.hpp#L29-L48
static void
ascon_hash_a(benchmark::State& state)
{
  uint8_t* msg = static_cast<uint8_t*>(malloc(MSG_LEN));
  uint8_t* digest = static_cast<uint8_t*>(malloc(DIG_LEN));

  ascon_utils::random_data(msg, MSG_LEN);
  memset(digest, 0, DIG_LEN);

  size_t itr = 0;
  for (auto _ : state) {
    ascon::hash_a(msg, MSG_LEN, digest);

    benchmark::DoNotOptimize(digest);
    memset(digest, 0, DIG_LEN);
    benchmark::DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>(MSG_LEN * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(msg);
  free(digest);
}

// Benchmark Ascon-128 authenticated encryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/auth_enc.hpp#L12-L38
static void
ascon_128_enc(benchmark::State& state)
{
  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);

  using namespace ascon;
  using namespace benchmark;

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(encrypt_128(k, n, data, DATA_LEN, text, TEXT_LEN, enc));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + TEXT_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-128 verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L8-L36
static void
ascon_128_dec(benchmark::State& state)
{
  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));
  uint8_t* dec = static_cast<uint8_t*>(malloc(TEXT_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);
  memset(dec, 0, TEXT_LEN);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128(k, n, data, DATA_LEN, text, TEXT_LEN, enc);

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(decrypt_128(k, n, data, DATA_LEN, enc, CIPHER_LEN, dec, t));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + CIPHER_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

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
  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);

  using namespace ascon;
  using namespace benchmark;

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(encrypt_128a(k, n, data, DATA_LEN, text, TEXT_LEN, enc));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + TEXT_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-128a verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L38-L66
static void
ascon_128a_dec(benchmark::State& state)
{
  uint8_t bytes[16];

  ascon_utils::random_data(bytes, 16);
  const ascon::secret_key_128_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));
  uint8_t* dec = static_cast<uint8_t*>(malloc(TEXT_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);
  memset(dec, 0, TEXT_LEN);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_128a(k, n, data, DATA_LEN, text, TEXT_LEN, enc);

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(decrypt_128a(k, n, data, DATA_LEN, enc, CIPHER_LEN, dec, t));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + CIPHER_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

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
  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);

  using namespace ascon;
  using namespace benchmark;

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(encrypt_80pq(k, n, data, DATA_LEN, text, TEXT_LEN, enc));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + TEXT_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(data);
  free(text);
  free(enc);
}

// Benchmark Ascon-80pq verified decryption
// https://github.com/itzmeanjan/ascon/blob/970c29902474eb55777761990eedf47189c75ff4/include/verf_dec.hpp#L8-L36
static void
ascon_80pq_dec(benchmark::State& state)
{
  uint8_t bytes[20];

  ascon_utils::random_data(bytes, 20);
  const ascon::secret_key_160_t k{ bytes };

  ascon_utils::random_data(bytes, 16);
  const ascon::nonce_t n{ bytes };

  uint8_t* data = static_cast<uint8_t*>(malloc(DATA_LEN));
  uint8_t* text = static_cast<uint8_t*>(malloc(TEXT_LEN));
  uint8_t* enc = static_cast<uint8_t*>(malloc(CIPHER_LEN));
  uint8_t* dec = static_cast<uint8_t*>(malloc(TEXT_LEN));

  ascon_utils::random_data(data, DATA_LEN);
  ascon_utils::random_data(text, TEXT_LEN);

  memset(enc, 0, CIPHER_LEN);
  memset(dec, 0, TEXT_LEN);

  using namespace benchmark;
  using namespace ascon;
  const tag_t t = encrypt_80pq(k, n, data, DATA_LEN, text, TEXT_LEN, enc);

  size_t itr = 0;
  for (auto _ : state) {
    DoNotOptimize(decrypt_80pq(k, n, data, DATA_LEN, enc, CIPHER_LEN, dec, t));
    DoNotOptimize(itr++);
  }
  state.SetBytesProcessed(static_cast<int64_t>((DATA_LEN + CIPHER_LEN) * itr));
  state.SetItemsProcessed(static_cast<int64_t>(itr));

  free(data);
  free(text);
  free(enc);
  free(dec);
}

// register for benchmarking
BENCHMARK(ascon_hash);
BENCHMARK(ascon_hash_a);
BENCHMARK(ascon_128_enc);
BENCHMARK(ascon_128_dec);
BENCHMARK(ascon_128a_enc);
BENCHMARK(ascon_128a_dec);
BENCHMARK(ascon_80pq_enc);
BENCHMARK(ascon_80pq_dec);

// main function to make this program executable
BENCHMARK_MAIN();
