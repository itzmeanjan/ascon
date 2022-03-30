#pragma once
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>

// Utility functions for Ascon Light Weight Cryptography Implementation
namespace ascon_utils {

// Given big-endian byte array of length 8, this function interprets it as
// 64 -bit unsigned integer
static inline const uint64_t
from_be_bytes(const uint8_t* const i_bytes)
{
  return (static_cast<uint64_t>(i_bytes[0]) << 56) |
         (static_cast<uint64_t>(i_bytes[1]) << 48) |
         (static_cast<uint64_t>(i_bytes[2]) << 40) |
         (static_cast<uint64_t>(i_bytes[3]) << 32) |
         (static_cast<uint64_t>(i_bytes[4]) << 24) |
         (static_cast<uint64_t>(i_bytes[5]) << 16) |
         (static_cast<uint64_t>(i_bytes[6]) << 8) |
         static_cast<uint64_t>(i_bytes[7]);
}

// Given a 64 -bit unsigned integer, this function interprets it as a big-endian
// byte array
static inline void
to_be_bytes(const uint64_t num, uint8_t* const bytes)
{
#pragma unroll 8
  for (size_t i = 0; i < 8; i++) {
    bytes[i] = static_cast<uint8_t>(num >> ((8u - (i + 1u)) << 3u));
  }
}

// Generate `len` -many random 64 -bit unsigned integers
static inline void
random_data(uint64_t* const data, const size_t len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

// Generate `len` -many random 8 -bit unsigned integers
static inline void
random_data(uint8_t* const data, const size_t len)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint8_t> dis;

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

// Pad data when rate = 64, such that padded data (bit-) length is evenly
// divisible by rate ( = 64 ).
//
// See Ascon-{128, Hash, HashA} padding rule in section 2.4.{2,3} & 2.5.2 of
// Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline const uint64_t
pad_data(const uint8_t* const data, const size_t pad_byte_len)
{
  uint64_t data_blk;

  switch (pad_byte_len) {
    case 8:
      data_blk = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      break;
    case 7:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      break;
    case 6:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      break;
    case 5:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      break;
    case 4:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      break;
    case 3:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      break;
    case 2:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (static_cast<uint64_t>(data[5]) << 16) |
                 (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      break;
    case 1:
      data_blk = (static_cast<uint64_t>(data[0]) << 56) |
                 (static_cast<uint64_t>(data[1]) << 48) |
                 (static_cast<uint64_t>(data[2]) << 40) |
                 (static_cast<uint64_t>(data[3]) << 32) |
                 (static_cast<uint64_t>(data[4]) << 24) |
                 (static_cast<uint64_t>(data[5]) << 16) |
                 (static_cast<uint64_t>(data[6]) << 8) |
                 (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      break;
  }

  return data_blk;
}

// Pad data, when rate = 128, such that padded data (bit-) length is evenly
// divisible by rate ( = 128 ).
//
// See Ascon-128a padding rule in section 2.4.{2,3} of Ascon specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
static inline void
pad_data(
  const uint8_t* const __restrict data,
  const size_t pad_byte_len,
  uint64_t* const __restrict data_blk // padded block; assert len(data_blk) = 2
)
{
  switch (pad_byte_len) {
    case 16:
      data_blk[0] = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 15:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 14:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 13:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 12:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 11:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 10:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 9:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      data_blk[1] = 0b0ul /* ++ '0' <64 bits> */;
      break;
    case 8:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = 0b1ul << 63 /* padding: '1' ++ '0' <63 bits> */;
      break;
    case 7:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (0b1ul << 55) /* padding: '1' ++ '0' <55 bits> */;
      break;
    case 6:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (0b1ul << 47) /* padding: '1' ++ '0' <47 bits> */;
      break;
    case 5:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (0b1ul << 39) /* padding: '1' ++ '0' <39 bits> */;
      break;
    case 4:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (0b1ul << 31) /* padding: '1' ++ '0' <31 bits> */;
      break;
    case 3:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (0b1ul << 23) /* padding: '1' ++ '0' <23 bits> */;
      break;
    case 2:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (static_cast<uint64_t>(data[13]) << 16) |
                    (0b1ul << 15) /* padding: '1' ++ '0' <15 bits> */;
      break;
    case 1:
      data_blk[0] = (static_cast<uint64_t>(data[0]) << 56) |
                    (static_cast<uint64_t>(data[1]) << 48) |
                    (static_cast<uint64_t>(data[2]) << 40) |
                    (static_cast<uint64_t>(data[3]) << 32) |
                    (static_cast<uint64_t>(data[4]) << 24) |
                    (static_cast<uint64_t>(data[5]) << 16) |
                    (static_cast<uint64_t>(data[6]) << 8) |
                    static_cast<uint64_t>(data[7]);
      data_blk[1] = (static_cast<uint64_t>(data[8]) << 56) |
                    (static_cast<uint64_t>(data[9]) << 48) |
                    (static_cast<uint64_t>(data[10]) << 40) |
                    (static_cast<uint64_t>(data[11]) << 32) |
                    (static_cast<uint64_t>(data[12]) << 24) |
                    (static_cast<uint64_t>(data[13]) << 16) |
                    (static_cast<uint64_t>(data[14]) << 8) |
                    (0b1ul << 7) /* padding: '1' ++ '0' <7 bits> */;
      break;
  }
}

// Converts byte array into hex string; see https://stackoverflow.com/a/14051107
const std::string
tohex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << (uint32_t)bytes[i];
  }
  return ss.str();
}

}
