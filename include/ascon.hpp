#pragma once
#include "auth_enc.hpp"
#include "hash.hpp"
#include "verf_dec.hpp"

namespace ascon_utils {

// Given 16 -bytes are interpreted as Ascon-128 & Ascon-128a secret key ( 128
// -bit )
static inline void
from_be_bytes(
  const uint8_t* const __restrict bytes, // 16 -bytes
  ascon::secret_key_128_t& key // 128 -bit secret key for Ascon-128 & Ascon-128a
)
{
  const uint64_t w0 = ascon_utils::from_be_bytes(bytes);
  const uint64_t w1 = ascon_utils::from_be_bytes(bytes + 8u);

  key.limbs[0] = w0;
  key.limbs[1] = w1;
}

// Given 20 -bytes are interpreted as Ascon-80pq secret key ( 160 -bit )
static inline void
from_be_bytes(const uint8_t* const __restrict bytes, // 20 -bytes
              ascon::secret_key_160_t& key // 160 -bit secret key for Ascon-80pq
)
{
  const uint64_t w0 = ascon_utils::from_be_bytes(bytes);
  const uint64_t w1 = ascon_utils::from_be_bytes(bytes + 8u);
  const uint32_t w2 = (static_cast<uint32_t>(bytes[16u]) << 24) |
                      (static_cast<uint32_t>(bytes[17u]) << 16) |
                      (static_cast<uint32_t>(bytes[18u]) << 8) |
                      static_cast<uint32_t>(bytes[19u]);

  key.limbs[0] = w0;
  key.limbs[1] = w1;
  key.limbs[2] = static_cast<uint64_t>(w2);
}

// Given 16 -bytes are interpreted as public message nonce for Ascon
// authenticated cipher suite
static inline void
from_be_bytes(const uint8_t* const __restrict bytes, // 16 -bytes
              ascon::nonce_t& nonce // 128 -bit nonce for Ascon-{128,128a,80pq}
)
{
  const uint64_t w0 = ascon_utils::from_be_bytes(bytes);
  const uint64_t w1 = ascon_utils::from_be_bytes(bytes + 8u);

  nonce.limbs[0] = w0;
  nonce.limbs[1] = w1;
}

// Given 16 -bytes are interpreted as authentication tag for Ascon authenticated
// cipher suite
static inline void
from_be_bytes(const uint8_t* const __restrict bytes, // 16 -bytes
              ascon::tag_t& tag // 128 -bit auth tag for Ascon-{128,128a,80pq}
)
{
  const uint64_t w0 = ascon_utils::from_be_bytes(bytes);
  const uint64_t w1 = ascon_utils::from_be_bytes(bytes + 8u);

  tag.limbs[0] = w0;
  tag.limbs[1] = w1;
}

}
