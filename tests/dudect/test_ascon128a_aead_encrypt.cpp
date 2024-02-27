#include "ascon/aead/ascon128a.hpp"
#include <cstdio>

#define DUDECT_IMPLEMENTATION
#define DUDECT_VISIBLITY_STATIC
#include "dudect.h"

constexpr size_t FIXED_AD_BYTE_LEN = 64;
constexpr size_t FIXED_PT_BYTE_LEN = 512;
constexpr size_t FIXED_CT_BYTE_LEN = FIXED_PT_BYTE_LEN;
constexpr size_t CHUNK_BYTE_LEN = ascon128a_aead::KEY_LEN + ascon128a_aead::NONCE_LEN + FIXED_AD_BYTE_LEN +
                                  FIXED_PT_BYTE_LEN + FIXED_CT_BYTE_LEN + ascon128a_aead::TAG_LEN;

uint8_t
do_one_computation(uint8_t* const data)
{
  constexpr size_t key_begin = 0;
  constexpr size_t nonce_begin = key_begin + ascon128a_aead::KEY_LEN;
  constexpr size_t ad_begin = nonce_begin + ascon128a_aead::NONCE_LEN;
  constexpr size_t pt_begin = ad_begin + FIXED_AD_BYTE_LEN;
  constexpr size_t ct_begin = pt_begin + FIXED_PT_BYTE_LEN;
  constexpr size_t tag_begin = ct_begin + FIXED_CT_BYTE_LEN;
  constexpr size_t tag_end = tag_begin + ascon128a_aead::TAG_LEN;

  static_assert(tag_end == CHUNK_BYTE_LEN, "Must compute byte offsets correctly !");

  auto key = std::span<const uint8_t, ascon128a_aead::KEY_LEN>(data + key_begin, nonce_begin - key_begin);
  auto nonce = std::span<const uint8_t, ascon128a_aead::NONCE_LEN>(data + nonce_begin, ad_begin - nonce_begin);
  auto ad = std::span<const uint8_t, FIXED_AD_BYTE_LEN>(data + ad_begin, pt_begin - ad_begin);
  auto ptxt = std::span<const uint8_t, FIXED_PT_BYTE_LEN>(data + pt_begin, ct_begin - pt_begin);
  auto ctxt = std::span<uint8_t, FIXED_CT_BYTE_LEN>(data + ct_begin, tag_begin - ct_begin);
  auto tag = std::span<uint8_t, ascon128a_aead::TAG_LEN>(data + tag_begin, tag_end - tag_begin);

  uint8_t ret_val = 0;

  ascon128a_aead::encrypt(key, nonce, ad, ptxt, ctxt, tag);

  ret_val ^= (ctxt[0] ^ ctxt[ctxt.size() - 1]) ^ (tag[0] ^ tag[tag.size() - 1]);
  return ret_val;
}

void
prepare_inputs(dudect_config_t* const c, uint8_t* const input_data, uint8_t* const classes)
{
  randombytes(input_data, c->number_measurements * c->chunk_size);

  for (size_t i = 0; i < c->number_measurements; i++) {
    classes[i] = randombit();
    if (classes[i] == 0) {
      std::memset(input_data + i * c->chunk_size, 0x00, c->chunk_size);
    }
  }
}

dudect_state_t
test_ascon128a_aead_encrypt()
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
  if (test_ascon128a_aead_encrypt() != DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
