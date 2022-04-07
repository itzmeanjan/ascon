#include "ascon.hpp"

// Ascon function prototypes, required as this translation unit will be compiled
// down to shared library object
extern "C"
{
  void hash(const uint8_t* const __restrict,
            const size_t,
            uint8_t* const __restrict);

  void hash_a(const uint8_t* const __restrict,
              const size_t,
              uint8_t* const __restrict);

  ascon::tag_t encrypt_128(const ascon::secret_key_128_t&,
                           const ascon::nonce_t&,
                           const uint8_t* const __restrict,
                           const size_t,
                           const uint8_t* const __restrict,
                           const size_t,
                           uint8_t* const __restrict);

  ascon::tag_t encrypt_128a(const ascon::secret_key_128_t&,
                            const ascon::nonce_t&,
                            const uint8_t* const __restrict,
                            const size_t,
                            const uint8_t* const __restrict,
                            const size_t,
                            uint8_t* const __restrict);

  ascon::tag_t encrypt_80pq(const ascon::secret_key_160_t&,
                            const ascon::nonce_t&,
                            const uint8_t* const __restrict,
                            const size_t,
                            const uint8_t* const __restrict,
                            const size_t,
                            uint8_t* const __restrict);

  bool decrypt_128(const ascon::secret_key_128_t&,
                   const ascon::nonce_t&,
                   const uint8_t* const __restrict,
                   const size_t,
                   const uint8_t* const __restrict,
                   const size_t,
                   uint8_t* const __restrict,
                   const ascon::tag_t&);

  bool decrypt_128a(const ascon::secret_key_128_t&,
                    const ascon::nonce_t&,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const ascon::tag_t&);

  bool decrypt_80pq(const ascon::secret_key_160_t&,
                    const ascon::nonce_t&,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const ascon::tag_t&);
}

// Slim `C` wrapper on top of `C++` implementation, so that it can be compiled
// down to shared library object with `C` ABI
extern "C"
{
  void hash(const uint8_t* const __restrict msg,
            const size_t msg_len,
            uint8_t* const __restrict digest)
  {
    ascon::hash(msg, msg_len, digest);
  }

  void hash_a(const uint8_t* const __restrict msg,
              const size_t msg_len,
              uint8_t* const __restrict digest)
  {
    ascon::hash_a(msg, msg_len, digest);
  }

  ascon::tag_t encrypt_128(const ascon::secret_key_128_t& k,
                           const ascon::nonce_t& n,
                           const uint8_t* const __restrict data,
                           const size_t data_len,
                           const uint8_t* const __restrict text,
                           const size_t text_len,
                           uint8_t* const __restrict cipher)
  {
    return ascon::encrypt_128(k, n, data, data_len, text, text_len, cipher);
  }

  ascon::tag_t encrypt_128a(const ascon::secret_key_128_t& k,
                            const ascon::nonce_t& n,
                            const uint8_t* const __restrict data,
                            const size_t data_len,
                            const uint8_t* const __restrict text,
                            const size_t text_len,
                            uint8_t* const __restrict cipher)
  {
    return ascon::encrypt_128a(k, n, data, data_len, text, text_len, cipher);
  }

  ascon::tag_t encrypt_80pq(const ascon::secret_key_160_t& k,
                            const ascon::nonce_t& n,
                            const uint8_t* const __restrict data,
                            const size_t data_len,
                            const uint8_t* const __restrict text,
                            const size_t text_len,
                            uint8_t* const __restrict cipher)
  {
    return ascon::encrypt_80pq(k, n, data, data_len, text, text_len, cipher);
  }

  bool decrypt_128(const ascon::secret_key_128_t& k,
                   const ascon::nonce_t& n,
                   const uint8_t* const __restrict data,
                   const size_t data_len,
                   const uint8_t* const __restrict enc,
                   const size_t enc_len,
                   uint8_t* const __restrict text,
                   const ascon::tag_t& t)
  {
    return ascon::decrypt_128(k, n, data, data_len, enc, enc_len, text, t);
  }

  bool decrypt_128a(const ascon::secret_key_128_t& k,
                    const ascon::nonce_t& n,
                    const uint8_t* const __restrict data,
                    const size_t data_len,
                    const uint8_t* const __restrict enc,
                    const size_t enc_len,
                    uint8_t* const __restrict text,
                    const ascon::tag_t& t)
  {
    return ascon::decrypt_128a(k, n, data, data_len, enc, enc_len, text, t);
  }

  bool decrypt_80pq(const ascon::secret_key_160_t& k,
                    const ascon::nonce_t& n,
                    const uint8_t* const __restrict data,
                    const size_t data_len,
                    const uint8_t* const __restrict enc,
                    const size_t enc_len,
                    uint8_t* const __restrict text,
                    const ascon::tag_t& t)
  {
    return ascon::decrypt_80pq(k, n, data, data_len, enc, enc_len, text, t);
  }
}
