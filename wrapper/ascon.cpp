#include "ascon.hpp"

// Ascon function prototypes, required as this translation unit will be compiled
// down to shared library object
extern "C"
{
  // 128 -bit secret key, conforming to C -linkage requirements
  struct secret_key_128_t
  {
    uint64_t limbs[2];
  };

  // 160 -bit secret key, conforming to C -linkage requirements
  struct secret_key_160_t
  {
    uint64_t limbs[3];
  };

  // 128 -bit public message nonce, conforming to C -linkage requirements
  struct nonce_t
  {
    uint64_t limbs[2];
  };

  // 128 -bit authentication tag, conforming to C -linkage requirements
  struct tag_t
  {
    uint64_t limbs[2];
  };

  void hash(const uint8_t* const __restrict,
            const size_t,
            uint8_t* const __restrict);

  void hash_a(const uint8_t* const __restrict,
              const size_t,
              uint8_t* const __restrict);

  tag_t encrypt_128(const secret_key_128_t&,
                    const nonce_t&,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict);

  tag_t encrypt_128a(const secret_key_128_t&,
                     const nonce_t&,
                     const uint8_t* const __restrict,
                     const size_t,
                     const uint8_t* const __restrict,
                     const size_t,
                     uint8_t* const __restrict);

  tag_t encrypt_80pq(const secret_key_160_t&,
                     const nonce_t&,
                     const uint8_t* const __restrict,
                     const size_t,
                     const uint8_t* const __restrict,
                     const size_t,
                     uint8_t* const __restrict);

  bool decrypt_128(const secret_key_128_t&,
                   const nonce_t&,
                   const uint8_t* const __restrict,
                   const size_t,
                   const uint8_t* const __restrict,
                   const size_t,
                   uint8_t* const __restrict,
                   const tag_t&);

  bool decrypt_128a(const secret_key_128_t&,
                    const nonce_t&,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const tag_t&);

  bool decrypt_80pq(const secret_key_160_t&,
                    const nonce_t&,
                    const uint8_t* const __restrict,
                    const size_t,
                    const uint8_t* const __restrict,
                    const size_t,
                    uint8_t* const __restrict,
                    const tag_t&);
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

  tag_t encrypt_128(const secret_key_128_t& k,
                    const nonce_t& n,
                    const uint8_t* const __restrict data,
                    const size_t data_len,
                    const uint8_t* const __restrict text,
                    const size_t text_len,
                    uint8_t* const __restrict enc)
  {
    const ascon::secret_key_128_t k_{ k.limbs[0], k.limbs[1] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };

    auto t = ascon::encrypt_128(k_, n_, data, data_len, text, text_len, enc);

    return tag_t{ { t.limbs[0], t.limbs[1] } };
  }

  tag_t encrypt_128a(const secret_key_128_t& k,
                     const nonce_t& n,
                     const uint8_t* const __restrict data,
                     const size_t data_len,
                     const uint8_t* const __restrict text,
                     const size_t text_len,
                     uint8_t* const __restrict enc)
  {
    const ascon::secret_key_128_t k_{ k.limbs[0], k.limbs[1] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };

    auto t = ascon::encrypt_128a(k_, n_, data, data_len, text, text_len, enc);

    return tag_t{ { t.limbs[0], t.limbs[1] } };
  }

  tag_t encrypt_80pq(const secret_key_160_t& k,
                     const nonce_t& n,
                     const uint8_t* const __restrict data,
                     const size_t data_len,
                     const uint8_t* const __restrict text,
                     const size_t text_len,
                     uint8_t* const __restrict enc)
  {
    const ascon::secret_key_160_t k_{ k.limbs[0], k.limbs[1], k.limbs[2] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };

    auto t = ascon::encrypt_80pq(k_, n_, data, data_len, text, text_len, enc);

    return tag_t{ { t.limbs[0], t.limbs[1] } };
  }

  bool decrypt_128(const secret_key_128_t& k,
                   const nonce_t& n,
                   const uint8_t* const __restrict data,
                   const size_t data_len,
                   const uint8_t* const __restrict enc,
                   const size_t enc_len,
                   uint8_t* const __restrict text,
                   const tag_t& t)
  {
    const ascon::secret_key_128_t k_{ k.limbs[0], k.limbs[1] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };
    const ascon::tag_t t_{ t.limbs[0], t.limbs[1] };

    return ascon::decrypt_128(k_, n_, data, data_len, enc, enc_len, text, t_);
  }

  bool decrypt_128a(const secret_key_128_t& k,
                    const nonce_t& n,
                    const uint8_t* const __restrict data,
                    const size_t data_len,
                    const uint8_t* const __restrict enc,
                    const size_t enc_len,
                    uint8_t* const __restrict text,
                    const tag_t& t)
  {
    const ascon::secret_key_128_t k_{ k.limbs[0], k.limbs[1] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };
    const ascon::tag_t t_{ t.limbs[0], t.limbs[1] };

    return ascon::decrypt_128a(k_, n_, data, data_len, enc, enc_len, text, t_);
  }

  bool decrypt_80pq(const secret_key_160_t& k,
                    const nonce_t& n,
                    const uint8_t* const __restrict data,
                    const size_t data_len,
                    const uint8_t* const __restrict enc,
                    const size_t enc_len,
                    uint8_t* const __restrict text,
                    const tag_t& t)
  {
    const ascon::secret_key_160_t k_{ k.limbs[0], k.limbs[1], k.limbs[2] };
    const ascon::nonce_t n_{ n.limbs[0], n.limbs[1] };
    const ascon::tag_t t_{ t.limbs[0], t.limbs[1] };

    return ascon::decrypt_80pq(k_, n_, data, data_len, enc, enc_len, text, t_);
  }
}
