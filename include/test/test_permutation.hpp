#pragma once
#include "hash.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Testing permutation `p_a` by calculating initial Ascon-{Hash, HashA, XOF,
// XOFA} state; see precomputed hash states for all these hashing algorithms in
// section 2.5.1 of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
void
p_a()
{
  {
    uint64_t state[5] = { 0x00400c0000000100ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == ascon_hash_utils::ASCON_HASH_INIT_STATE[0]);
    assert(state[1] == ascon_hash_utils::ASCON_HASH_INIT_STATE[1]);
    assert(state[2] == ascon_hash_utils::ASCON_HASH_INIT_STATE[2]);
    assert(state[3] == ascon_hash_utils::ASCON_HASH_INIT_STATE[3]);
    assert(state[4] == ascon_hash_utils::ASCON_HASH_INIT_STATE[4]);
  }

  {
    uint64_t state[5] = { 0x00400c0400000100ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == ascon_hash_utils::ASCON_HASHA_INIT_STATE[0]);
    assert(state[1] == ascon_hash_utils::ASCON_HASHA_INIT_STATE[1]);
    assert(state[2] == ascon_hash_utils::ASCON_HASHA_INIT_STATE[2]);
    assert(state[3] == ascon_hash_utils::ASCON_HASHA_INIT_STATE[3]);
    assert(state[4] == ascon_hash_utils::ASCON_HASHA_INIT_STATE[4]);
  }

  {
    uint64_t state[5] = { 0x00400c0000000000ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0xb57e273b814cd416ul);
    assert(state[1] == 0x2b51042562ae2420ul);
    assert(state[2] == 0x66a3a7768ddf2218ul);
    assert(state[3] == 0x5aad0a7a8153650cul);
    assert(state[4] == 0x4f3e0e32539493b6ul);
  }

  {
    uint64_t state[5] = { 0x00400c0400000000ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0x44906568b77b9832ul);
    assert(state[1] == 0xcd8d6cae53455532ul);
    assert(state[2] == 0xf7b5212756422129ul);
    assert(state[3] == 0x246885e1de0d225bul);
    assert(state[4] == 0xa8cb5ce33449973ful);
  }
}

}
