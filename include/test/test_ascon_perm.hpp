#pragma once
#include "permutation.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Testing permutation `p_a` by calculating initial Ascon-{Hash, HashA, XOF,
// XOFA} state; see precomputed hash states for all these hashing algorithms in
// section 2.5.1 of Ascon specification
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
inline void
p_a()
{
  {
    uint64_t state[5]{ 0x00400c0000000100ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0xee9398aadb67f03dul);
    assert(state[1] == 0x8bb21831c60f1002ul);
    assert(state[2] == 0xb48a92db98d5da62ul);
    assert(state[3] == 0x43189921b8f8e3e8ul);
    assert(state[4] == 0x348fa5c9d525e140ul);
  }

  {
    uint64_t state[5]{ 0x00400c0400000100ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0x01470194fc6528a6ul);
    assert(state[1] == 0x738ec38ac0adffa7ul);
    assert(state[2] == 0x2ec8e3296c76384cul);
    assert(state[3] == 0xd6f6a54d7f52377dul);
    assert(state[4] == 0xa13c42a223be8d87ul);
  }

  {
    uint64_t state[5]{ 0x00400c0000000000ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0xb57e273b814cd416ul);
    assert(state[1] == 0x2b51042562ae2420ul);
    assert(state[2] == 0x66a3a7768ddf2218ul);
    assert(state[3] == 0x5aad0a7a8153650cul);
    assert(state[4] == 0x4f3e0e32539493b6ul);
  }

  {
    uint64_t state[5]{ 0x00400c0400000000ul, 0ul, 0ul, 0ul, 0ul };
    ascon_perm::permute<12>(state);

    assert(state[0] == 0x44906568b77b9832ul);
    assert(state[1] == 0xcd8d6cae53455532ul);
    assert(state[2] == 0xf7b5212756422129ul);
    assert(state[3] == 0x246885e1de0d225bul);
    assert(state[4] == 0xa8cb5ce33449973ful);
  }
}

}
