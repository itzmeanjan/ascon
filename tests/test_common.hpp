#pragma once
#include <cstddef>
#include <cstdint>

// Min. and max. byte length of associated data.
constexpr size_t MIN_AD_LEN = 0;
constexpr size_t MAX_AD_LEN = 64;

// Min. and max. byte length of plain/ cipher text.
constexpr size_t MIN_CT_LEN = 0;
constexpr size_t MAX_CT_LEN = 128;

// Min. and max. byte length of message to be absorbed into sponge.
constexpr size_t MIN_MSG_LEN = 0;
constexpr size_t MAX_MSG_LEN = 1024;

// Min. and max. byte length of output to be squeezed from sponge.
constexpr size_t MIN_OUT_LEN = 0;
constexpr size_t MAX_OUT_LEN = 256;
