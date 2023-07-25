#include "ascon_perm.hpp"
#include <gtest/gtest.h>

// See section 2.5.1 of Ascon v1.2 spec.
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf for following test
// cases.

TEST(AsconCipherSuite, AsconPermWithAsconHashIV)
{
  ascon_perm::ascon_perm_t perm({ 0x00400c0000000100ul, 0ul, 0ul, 0ul, 0ul });
  perm.permute<12>();

  ASSERT_EQ(perm.reveal(),
            ascon_perm::ascon_perm_t({ 0xee9398aadb67f03dul,
                                       0x8bb21831c60f1002ul,
                                       0xb48a92db98d5da62ul,
                                       0x43189921b8f8e3e8ul,
                                       0x348fa5c9d525e140ul })
              .reveal());
}

TEST(AsconCipherSuite, AsconPermWithAsconHashAIV)
{
  ascon_perm::ascon_perm_t perm({ 0x00400c0400000100ul, 0ul, 0ul, 0ul, 0ul });
  perm.permute<12>();

  ASSERT_EQ(perm.reveal(),
            ascon_perm::ascon_perm_t({ 0x01470194fc6528a6,
                                       0x738ec38ac0adffa7,
                                       0x2ec8e3296c76384c,
                                       0xd6f6a54d7f52377d,
                                       0xa13c42a223be8d87 })
              .reveal());
}

TEST(AsconCipherSuite, AsconPermWithAsconXofIV)
{
  ascon_perm::ascon_perm_t perm({ 0x00400c0000000000ul, 0ul, 0ul, 0ul, 0ul });
  perm.permute<12>();

  ASSERT_EQ(perm.reveal(),
            ascon_perm::ascon_perm_t({ 0xb57e273b814cd416,
                                       0x2b51042562ae2420,
                                       0x66a3a7768ddf2218,
                                       0x5aad0a7a8153650c,
                                       0x4f3e0e32539493b6 })
              .reveal());
}

TEST(AsconCipherSuite, AsconPermWithAsconXofAIV)
{
  ascon_perm::ascon_perm_t perm({ 0x00400c0400000000ul, 0ul, 0ul, 0ul, 0ul });
  perm.permute<12>();

  ASSERT_EQ(perm.reveal(),
            ascon_perm::ascon_perm_t({ 0x44906568b77b9832,
                                       0xcd8d6cae53455532,
                                       0xf7b5212756422129,
                                       0x246885e1de0d225b,
                                       0xa8cb5ce33449973f })
              .reveal());
}
