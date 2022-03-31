#pragma once
#include "hash.hpp"
#include <cassert>

// Test Ascon Light Weight Cryptography Implementation
namespace ascon_test {

// Testing Ascon Hash implementation for input length 0;
// test data generated using
// https://github.com/meichlseder/pyascon/blob/40fddd3e4009dbcc54eefd36033f7d418ba234f6/genkat.py
static void
hash()
{
  const uint8_t expect[32] = { 115, 70,  188, 20,  240, 54, 232, 122,
                               224, 61,  9,   151, 145, 48, 136, 245,
                               246, 132, 17,  67,  75,  60, 248, 181,
                               79,  167, 150, 168, 13,  37, 31,  145 };

  uint8_t digest[32];
  ascon::hash(nullptr, 0, digest);

  for (size_t i = 0; i < 32; i++) {
    assert(expect[i] == digest[i]);
  }
}

// Testing Ascon HashA implementation for input length 0;
// test data generated using
// https://github.com/meichlseder/pyascon/blob/40fddd3e4009dbcc54eefd36033f7d418ba234f6/genkat.py
static void
hash_a()
{
  const uint8_t expect[32] = { 174, 205, 2,   112, 38,  208, 103, 95,
                               157, 231, 168, 173, 140, 207, 81,  45,
                               182, 75,  30,  220, 240, 178, 12,  56,
                               138, 12,  124, 198, 23,  170, 162, 196 };

  uint8_t digest[32];
  ascon::hash_a(nullptr, 0, digest);

  for (size_t i = 0; i < 32; i++) {
    assert(expect[i] == digest[i]);
  }
}

}
