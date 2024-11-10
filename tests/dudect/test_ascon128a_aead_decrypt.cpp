#include "ascon/aead/ascon128a.hpp"
#include <cstdio>

#define DUDECT_IMPLEMENTATION
#define DUDECT_VISIBLITY_STATIC
#include "dudect.h"

constexpr size_t FIXED_AD_BYTE_LEN = 64;                // Associated Data
constexpr size_t FIXED_PT_BYTE_LEN = 512;               // Plain Text
constexpr size_t FIXED_CT_BYTE_LEN = FIXED_PT_BYTE_LEN; // Cipher Text
constexpr size_t FIXED_DT_BYTE_LEN = FIXED_CT_BYTE_LEN; // Deciphered Text

constexpr size_t CHUNK_BYTE_LEN =
  ascon128a_aead::KEY_LEN + ascon128a_aead::NONCE_LEN + FIXED_AD_BYTE_LEN + FIXED_PT_BYTE_LEN + FIXED_CT_BYTE_LEN + ascon128a_aead::TAG_LEN + FIXED_DT_BYTE_LEN;

constexpr size_t KEY_BEGIN = 0;
constexpr size_t NONCE_BEGIN = KEY_BEGIN + ascon128a_aead::KEY_LEN;
constexpr size_t AD_BEGIN = NONCE_BEGIN + ascon128a_aead::NONCE_LEN;
constexpr size_t PT_BEGIN = AD_BEGIN + FIXED_AD_BYTE_LEN;
constexpr size_t CT_BEGIN = PT_BEGIN + FIXED_PT_BYTE_LEN;
constexpr size_t TAG_BEGIN = CT_BEGIN + FIXED_CT_BYTE_LEN;
constexpr size_t DT_BEGIN = TAG_BEGIN + ascon128a_aead::TAG_LEN;
constexpr size_t DT_END = DT_BEGIN + FIXED_DT_BYTE_LEN;

static_assert(DT_END == CHUNK_BYTE_LEN, "Must compute byte offsets correctly !");

uint8_t
do_one_computation(uint8_t* const data)
{
  auto key = std::span<const uint8_t, ascon128a_aead::KEY_LEN>(data + KEY_BEGIN, NONCE_BEGIN - KEY_BEGIN);
  auto nonce = std::span<const uint8_t, ascon128a_aead::NONCE_LEN>(data + NONCE_BEGIN, AD_BEGIN - NONCE_BEGIN);
  auto ad = std::span<const uint8_t, FIXED_AD_BYTE_LEN>(data + AD_BEGIN, PT_BEGIN - AD_BEGIN);
  auto ptxt = std::span<const uint8_t, FIXED_PT_BYTE_LEN>(data + PT_BEGIN, CT_BEGIN - PT_BEGIN);
  auto ctxt = std::span<const uint8_t, FIXED_CT_BYTE_LEN>(data + CT_BEGIN, TAG_BEGIN - CT_BEGIN);
  auto tag = std::span<const uint8_t, ascon128a_aead::TAG_LEN>(data + TAG_BEGIN, DT_BEGIN - TAG_BEGIN);
  auto dtxt = std::span<uint8_t, FIXED_DT_BYTE_LEN>(data + DT_BEGIN, DT_END - DT_BEGIN);

  uint8_t ret_val = 0;

  const bool flag = ascon128a_aead::decrypt(key, nonce, ad, ctxt, dtxt, tag);

  ret_val ^= static_cast<uint8_t>(flag) ^ (dtxt[0] ^ dtxt[dtxt.size() - 1]);
  return ret_val;
}

void
prepare_inputs(dudect_config_t* const c, uint8_t* const input_data, uint8_t* const classes)
{
  randombytes(input_data, c->number_measurements * c->chunk_size);

  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();

    // Generate a valid cipher text and tag
    std::array<uint8_t, ascon128a_aead::TAG_LEN> tag{};

    const size_t chunk_begin = i * c->chunk_size;
    uint8_t* chunk = input_data + chunk_begin;

    auto key = std::span<const uint8_t, ascon128a_aead::KEY_LEN>(chunk + KEY_BEGIN, NONCE_BEGIN - KEY_BEGIN);
    auto nonce = std::span<const uint8_t, ascon128a_aead::NONCE_LEN>(chunk + NONCE_BEGIN, AD_BEGIN - NONCE_BEGIN);
    auto ad = std::span<const uint8_t, FIXED_AD_BYTE_LEN>(chunk + AD_BEGIN, PT_BEGIN - AD_BEGIN);
    auto ptxt = std::span<const uint8_t, FIXED_PT_BYTE_LEN>(chunk + PT_BEGIN, CT_BEGIN - PT_BEGIN);
    auto ctxt = std::span<uint8_t, FIXED_CT_BYTE_LEN>(chunk + CT_BEGIN, TAG_BEGIN - CT_BEGIN);

    ascon128a_aead::encrypt(key, nonce, ad, ptxt, ctxt, tag);

    if (classes[i] == 0) {
      // Keep the tag valid
      auto _tag = std::span<uint8_t, ascon128a_aead::TAG_LEN>(chunk + TAG_BEGIN, DT_BEGIN - TAG_BEGIN);
      std::copy(tag.begin(), tag.end(), _tag.begin());
    } else {
      // Maintain invalid tag
    }
  }
}

dudect_state_t
test_ascon128a_aead_decrypt()
{
  constexpr size_t chunk_size = CHUNK_BYTE_LEN;
  constexpr size_t number_measurements = 1e5;

  dudect_config_t config = {
    chunk_size,
    number_measurements,
  };
  dudect_ctx_t ctx;
  dudect_init(&ctx, &config);

  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }

  dudect_free(&ctx);

  printf("Detected timing leakage in \"%s\", defined in file \"%s\"\n", __func__, __FILE_NAME__);
  return state;
}

int
main()
{
  if (test_ascon128a_aead_decrypt() != DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
