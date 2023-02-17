#include "aead.hpp"
#include "hash.hpp"

// Ascon Hash, AEAD function prototypes, required as this translation unit will
// be compiled down to a shared library object
extern "C"
{
  void hash(const uint8_t* const __restrict,
            const size_t,
            uint8_t* const __restrict);

  void hash_a(const uint8_t* const __restrict,
              const size_t,
              uint8_t* const __restrict);

  void xof(const uint8_t* const __restrict,
           const size_t,
           uint8_t* const __restrict,
           const size_t);

  void xofa(const uint8_t* const __restrict,
            const size_t,
            uint8_t* const __restrict,
            const size_t);

  void encrypt_128(const uint8_t* const __restrict,
                   const uint8_t* const __restrict,
                   const uint8_t* const __restrict,
                   const size_t,
                   const uint8_t* const __restrict,
                   const size_t,
                   uint8_t* const __restrict,
                   uint8_t* const __restrict tag);

  bool decrypt_128(const uint8_t* const __restrict,
                   const uint8_t* const __restrict,
                   const uint8_t* const __restrict,
                   const size_t,
                   const uint8_t* const __restrict,
                   const size_t,
                   uint8_t* const __restrict,
                   const uint8_t* const __restrict);

  void encrypt_128a(const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    uint8_t* const __restrict tag);

  bool decrypt_128a(const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const uint8_t* const __restrict);

  void encrypt_80pq(const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    uint8_t* const __restrict tag);

  bool decrypt_80pq(const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const uint8_t* const __restrict);
}

// Slim `C` wrapper on top of `C++` implementation, so that it can be compiled
// down to a shared library object with `C` conformant ABI
extern "C"
{
  void hash(const uint8_t* const __restrict msg,
            const size_t msg_len,
            uint8_t* const __restrict digest)
  {
    ascon::ascon_hash hasher;
    hasher.hash(msg, msg_len);
    hasher.digest(digest);
  }

  void hash_a(const uint8_t* const __restrict msg,
              const size_t msg_len,
              uint8_t* const __restrict digest)
  {
    ascon::ascon_hasha hasher;
    hasher.hash(msg, msg_len);
    hasher.digest(digest);
  }

  void xof(const uint8_t* const __restrict msg,
           const size_t msg_len,
           uint8_t* const __restrict digest,
           const size_t dig_len)
  {
    ascon::ascon_xof hasher;
    hasher.hash(msg, msg_len);
    hasher.read(digest, dig_len);
  }

  void xofa(const uint8_t* const __restrict msg,
            const size_t msg_len,
            uint8_t* const __restrict digest,
            const size_t dig_len)
  {
    ascon::ascon_xofa hasher;
    hasher.hash(msg, msg_len);
    hasher.read(digest, dig_len);
  }

  void encrypt_128(const uint8_t* const __restrict key,
                   const uint8_t* const __restrict nonce,
                   const uint8_t* const __restrict data,
                   const size_t dlen,
                   const uint8_t* const __restrict text,
                   const size_t ctlen,
                   uint8_t* const __restrict enc,
                   uint8_t* const __restrict tag)
  {
    ascon::encrypt_128(key, nonce, data, dlen, text, ctlen, enc, tag);
  }

  void encrypt_128a(const uint8_t* const __restrict key,
                    const uint8_t* const __restrict nonce,
                    const uint8_t* const __restrict data,
                    const size_t dlen,
                    const uint8_t* const __restrict text,
                    const size_t ctlen,
                    uint8_t* const __restrict enc,
                    uint8_t* const __restrict tag)
  {
    ascon::encrypt_128a(key, nonce, data, dlen, text, ctlen, enc, tag);
  }

  void encrypt_80pq(const uint8_t* const __restrict key,
                    const uint8_t* const __restrict nonce,
                    const uint8_t* const __restrict data,
                    const size_t dlen,
                    const uint8_t* const __restrict text,
                    const size_t ctlen,
                    uint8_t* const __restrict enc,
                    uint8_t* const __restrict tag)
  {
    ascon::encrypt_80pq(key, nonce, data, dlen, text, ctlen, enc, tag);
  }

  bool decrypt_128(const uint8_t* const __restrict key,
                   const uint8_t* const __restrict nonce,
                   const uint8_t* const __restrict data,
                   const size_t dlen,
                   const uint8_t* const __restrict enc,
                   const size_t ctlen,
                   uint8_t* const __restrict text,
                   const uint8_t* const __restrict tag)
  {
    return ascon::decrypt_128(key, nonce, data, dlen, enc, ctlen, text, tag);
  }

  bool decrypt_128a(const uint8_t* const __restrict key,
                    const uint8_t* const __restrict nonce,
                    const uint8_t* const __restrict data,
                    const size_t dlen,
                    const uint8_t* const __restrict enc,
                    const size_t ctlen,
                    uint8_t* const __restrict text,
                    const uint8_t* const __restrict tag)
  {
    return ascon::decrypt_128a(key, nonce, data, dlen, enc, ctlen, text, tag);
  }

  bool decrypt_80pq(const uint8_t* const __restrict key,
                    const uint8_t* const __restrict nonce,
                    const uint8_t* const __restrict data,
                    const size_t dlen,
                    const uint8_t* const __restrict enc,
                    const size_t ctlen,
                    uint8_t* const __restrict text,
                    const uint8_t* const __restrict tag)
  {
    return ascon::decrypt_80pq(key, nonce, data, dlen, enc, ctlen, text, tag);
  }
}
