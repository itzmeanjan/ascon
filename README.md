# ascon
Ascon Permutation-based Lightweight Cryptography Standards for Constrained Devices: Authenticated Encryption, Hash, and Extendable Output Functions.

## Overview
This header-only C++ library implements the whole Ascon LwC cipher-suite i.e. Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128. These algorithms, suitable for constrained environments, are part of the Ascon family designed for resource-limited devices, prioritizing security, performance, and efficiency. The library offers `constexpr` functions where possible for enhanced performance and simplifies integration. The implementation conforms to the Ascon draft standard defined in [NIST SP 800-232](https://doi.org/10.6028/NIST.SP.800-232.ipd).

The library includes the following core Ascon cryptographic primitives:

* **Ascon-AEAD128:** Offers AEAD, encrypting the plaintext and authenticating both the ciphertext and associated data to ensure confidentiality and authenticity.
* **Ascon-Hash256:** A cryptographic hash function generating a 256-bit digest for data integrity verification and other cryptographic applications.
* **Ascon-XOF128:** An extendable output function (XOF) that produces variable-length outputs, useful in various cryptographic contexts where flexibility in output length is required.
* **Ascon-CXOF128:** A customizable XOF variant, offering additional flexibility by allowing for application-specific parameterization through a customization string.

> [!NOTE]
> All these schemes offer incremental API - meaning data absorption and squeezing can be performed by making multiple consecutive calls to the corresponding function, as long as that phase it not finalized. It is beneficial when working with large input/ output, which doesn't fit in-memory.

This implementation leverages a sponge construction built upon the Ascon permutation. It employs `std::span` for safe memory handling and provides `constexpr` functions where feasible for optimized compile-time computations for statically known inputs.

**Key Features:**
* **Header-Only:** Simple integration; no linking required.
* **`constexpr` Support:** Compile-time evaluation for optimized performance where applicable.
* **`std::span` Usage:** Type-safe memory management.
* **Thorough Testing:** Includes property based tests and known-answer tests (KATs).
* **Benchmarking Support:** Prepared for benchmarking with google-benchmark.

**Important Considerations:**
* **Unaudited:** This implementation has not yet undergone formal security audits. Production use requires careful consideration of the risks.
* **Associated Data (AEAD):** Associated data in Ascon-AEAD128 is authenticated but *not* encrypted.  Confidentiality is provided only for the plaintext.
* **Implementation Size:** While header-only, the actual size will depend on compiler optimizations and included features.

## Prerequisites

* A C++20-compliant compiler (e.g., g++, clang++).
* Build tools: `make` and `cmake`.
* For testing: google-test ([Installation Instructions](https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project)).
* For benchmarking: google-benchmark ([Installation Instructions](https://github.com/google/benchmark/#installation)).
* (Optional) For CPU cycle benchmarking: libPFM ([Installation Instructions](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7)). Requires building google-benchmark with libPFM support.

## Testing

This library includes a comprehensive test suite verifying the functional correctness of Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128.  Known Answer Tests (KATs) ensure conformance to the specification.

We incorporate KAT vectors from two sources.
- (a) Repo hosting, official implementation from Ascon team @ https://github.com/ascon/ascon-c.
- (b) NIST ACVP server @ https://github.com/usnistgov/ACVP-Server. You can sync latest ACVP KATs by running `$ make sync_acvp_kats`.

Run all tests using these commands (from the repository root):

```bash
make test -j               # Run release build tests
make debug_asan_test -j    # Run debug tests with AddressSanitizer (memory error detection)
make release_asan_test -j  # Run release tests with AddressSanitizer
make debug_ubsan_test -j   # Run debug tests with UndefinedBehaviorSanitizer
make release_ubsan_test -j # Run release tests with UndefinedBehaviorSanitizer
```

```bash
PASSED TESTS (73/73):
       2 ms: build/test/test.out AsconAEAD128.MultipleEncryptPlaintextCalls
       2 ms: build/test/test.out AsconAEAD128.ValidEncryptionSequence
       2 ms: build/test/test.out AsconHash256.AbsorbMessageAfterDigestIsProduced
       2 ms: build/test/test.out AsconCXOF128.MultipleFinalizeCalls
       2 ms: build/test/test.out AsconAEAD128.EncryptPlaintextAfterFinalizeEncrypt
       2 ms: build/test/test.out AsconHash256.MultipleProduceDigestCalls
       2 ms: build/test/test.out AsconAEAD128.MultipleDecryptCiphertextCalls
       2 ms: build/test/test.out AsconAEAD128.EncryptPlaintextBeforeFinalizeData
       2 ms: build/test/test.out AsconAEAD128.FinalizeDataWithoutAbsorb
       2 ms: build/test/test.out AsconHash256.MultipleFinalizeCalls
       2 ms: build/test/test.out AsconXof128.AbsorbMessageAfterFinalize
       2 ms: build/test/test.out AsconCXOF128.CustomizeAfterFinalization
       2 ms: build/test/test.out AsconHash256.CompileTimeComputeMessageDigest
       2 ms: build/test/test.out AsconHash256.MultipleAbsorbCalls
       2 ms: build/test/test.out AsconXof128.SqueezeWithoutFinalize
       2 ms: build/test/test.out AsconAEAD128.FinalizeEncryptBeforeFinalizeData
       2 ms: build/test/test.out AsconXof128.MultipleSqueezeCalls
       2 ms: build/test/test.out AsconXof128.ValidXofSequence
       2 ms: build/test/test.out AsconCXOF128.MultipleCustomizeCalls
       2 ms: build/test/test.out AsconCXOF128.FinalizeWithoutAbsorb
       2 ms: build/test/test.out AsconCXOF128.SqueezeWithoutFinalize
       2 ms: build/test/test.out AsconXof128.FinalizeDuringSqueezing
       2 ms: build/test/test.out AsconXof128.FinalizeWithoutAbsorb
       3 ms: build/test/test.out AsconHash256.ACVPKnownAnswerTests
       3 ms: build/test/test.out AsconAEAD128.MultipleAbsorbDataCalls
       3 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterDecrypt
       3 ms: build/test/test.out AsconCXOF128.MultipleAbsorbCalls
       3 ms: build/test/test.out AsconAEAD128.DecryptCiphertextAfterFinalizeDecrypt
       3 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterEncrypt
       3 ms: build/test/test.out AsconCXOF128.CompileTimeComputeCXOFOutput
       3 ms: build/test/test.out AsconCXOF128.CustomizeDuringSqueezing
       3 ms: build/test/test.out AsconCXOF128.AbsorbMessageAfterFinalization
       3 ms: build/test/test.out AsconCXOF128.FinalizeDuringSqueezing
       3 ms: build/test/test.out AsconCXOF128.AbsorbWithoutCustomize
       3 ms: build/test/test.out AsconAEAD128.ValidDecryptionSequence
       3 ms: build/test/test.out AsconAEAD128.FinalizeDataCalledTwice
       3 ms: build/test/test.out AsconCXOF128.CustomizeDuringAbsorption
       3 ms: build/test/test.out AsconCXOF128.AbsorbMessageDuringSqueezing
       3 ms: build/test/test.out AsconXof128.CompileTimeComputeXofOutput
       3 ms: build/test/test.out AsconHash256.DigestWithoutFinalize
       3 ms: build/test/test.out AsconHash256.AbsorbMessageAfterFinalize
       3 ms: build/test/test.out AsconXof128.MultipleAbsorbCalls
       4 ms: build/test/test.out AsconAEAD128.FinalizeEncryptCalledTwice
       4 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterFinalizeData
       4 ms: build/test/test.out AsconAEAD128.FinalizeDecryptBeforeFinalizeData
       4 ms: build/test/test.out AsconAEAD128.ACVPKnownAnswerTests
       4 ms: build/test/test.out AsconAEAD128.CompileTimeEncryptAndThenDecrypt
       4 ms: build/test/test.out AsconHash256.FinalizeAfterDigestIsProduced
       4 ms: build/test/test.out AsconXof128.AbsorbMessageDuringSqueezing
       4 ms: build/test/test.out AsconCXOF128.ACVPKnownAnswerTests
       5 ms: build/test/test.out AsconAEAD128.FinalizeDecryptCalledTwice
       5 ms: build/test/test.out AsconCXOF128.MultipleSqueezeCalls
       5 ms: build/test/test.out AsconXof128.MultipleFinalizeCalls
       5 ms: build/test/test.out AsconCXOF128.ValidCXOFSequence
       5 ms: build/test/test.out AsconHash256.FinalizeWithoutAbsorption
       6 ms: build/test/test.out AsconCXOF128.KnownAnswerTests
       6 ms: build/test/test.out AsconXof128.ACVPKnownAnswerTests
       6 ms: build/test/test.out AsconAEAD128.KnownAnswerTests
       6 ms: build/test/test.out AsconAEAD128.DecryptCiphertextBeforeFinalizeData
       8 ms: build/test/test.out AsconHash256.ValidHashingSequence
      11 ms: build/test/test.out AsconHash256.KnownAnswerTests
      11 ms: build/test/test.out AsconHash256.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameDigest
      13 ms: build/test/test.out AsconXof128.KnownAnswerTests
     529 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInCipherText
     535 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInKey
     537 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInTag
     540 ms: build/test/test.out AsconAEAD128.ForSamePlaintextOneshotEncryptionAndIncrementalEncryptionProducesSameTag
     541 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInNonce
     545 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInAssociatedData
     550 ms: build/test/test.out AsconAEAD128.EncryptThenDecrypt
     556 ms: build/test/test.out AsconAEAD128.ForSameCiphertextOneshotDecryptionAndIncrementalDecryptionProducesSamePlaintext
     977 ms: build/test/test.out AsconXof128.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput
    6222 ms: build/test/test.out AsconCXOF128.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput
```

> [!NOTE]
> There is a help menu, which introduces you to all available commands; just run `make` from the root directory of this project.

## Benchmarking

This section details how to benchmark the performance of the implemented Ascon schemes for a range of input/ output sizes. The benchmarks measure throughput (bytes/second) and, optionally, cycles/byte if libPFM is used.

To run the benchmarks, execute the following commands from the repository root:

```bash
make benchmark -j  # Run benchmarks without CPU cycle counting
make perf -j       # Run benchmarks with CPU cycle counting (requires libPFM)
```

> [!CAUTION]
> Ensure that you've disabled CPU frequency scaling, when benchmarking, following this guide @ https://github.com/google/benchmark/blob/main/docs/reducing_variance.md.

### On 12th Gen Intel(R) Core(TM) i7-1260P


```bash
$ ./build/perf/perf.out --benchmark_min_warmup_time=.05 --benchmark_min_time=0.1s --benchmark_perf_counters=CYCLES --benchmark_counters_tabular=true

2025-06-24T12:26:17+04:00
Running ./build/perf/perf.out
Run on (16 X 4476.96 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.66, 0.72, 0.75
------------------------------------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations     CYCLES CYCLES/ BYTE bytes_per_second
------------------------------------------------------------------------------------------------------------------
ascon_aead128_encrypt/32/32           218 ns          218 ns       647861   1.01088k       15.795      279.846Mi/s
ascon_aead128_encrypt/32/256          603 ns          603 ns       232372   2.82204k      9.79876      455.836Mi/s
ascon_aead128_encrypt/32/2048        3719 ns         3716 ns        37706   17.3952k      8.36309       533.76Mi/s
ascon_aead128_encrypt/32/16384      28763 ns        28749 ns         4869   134.509k      8.19376      544.555Mi/s
ascon_hash256/32                      304 ns          304 ns       458926   1.42371k       44.491      100.367Mi/s
ascon_hash256/64                      441 ns          441 ns       319251   2.05356k      32.0869      138.435Mi/s
ascon_hash256/2048                   8801 ns         8797 ns        15690   41.1541k      20.0948       222.01Mi/s
ascon_hash256/16384                 69569 ns        69545 ns         2018    323.49k      19.7443      224.675Mi/s
ascon_permutation<1>                 6.52 ns         6.52 ns     21310975    30.4988     0.762469       5.7115Gi/s
ascon_permutation<8>                 26.8 ns         26.8 ns      5203520    125.093      3.12733      1.39183Gi/s
ascon_permutation<12>                38.8 ns         38.7 ns      3450091    177.924      4.44811      984.442Mi/s
ascon_permutation<16>                49.5 ns         49.5 ns      2828246    231.737      5.79343      770.708Mi/s
ascon_xof128/32/64                    452 ns          451 ns       307910   2.10692k       21.947      202.854Mi/s
ascon_xof128/64/64                    591 ns          591 ns       234636   2.75744k      21.5425      206.573Mi/s
ascon_xof128/2048/64                 9245 ns         9242 ns        14896   43.1936k      20.4515      217.945Mi/s
ascon_xof128/16384/64               71968 ns        71943 ns         1954   335.222k      20.3807      218.033Mi/s
ascon_xof128/32/512                  2401 ns         2400 ns        58618   11.1967k      20.5821      216.152Mi/s
ascon_xof128/64/512                  2530 ns         2529 ns        55372   11.8428k      20.5604      217.227Mi/s
ascon_xof128/2048/512               11197 ns        11194 ns        12540   52.3059k       20.432      218.095Mi/s
ascon_xof128/16384/512              73831 ns        73811 ns         1902   344.367k      20.3816      218.306Mi/s
```

More detailed JSON benchmark result @ [bench_result_on_Linux_6.14.0-22-generic_x86_64_with_g++_14.json](./bench_result_on_Linux_6.14.0-22-generic_x86_64_with_g++_14.json).

## Usage

This section demonstrates how to use the Ascon header-only C++ library for authenticated encryption (AEAD), hashing, and extendable output functions (XOFs).

### Ascon-AEAD128

Ascon-AEAD128 provides authenticated encryption with associated data. The associated data is authenticated but not encrypted.

```cpp
#include "ascon/aead/ascon_aead128.hpp"
#include <array>
#include <iostream>

int main() {
  // Key, Nonce, and Associated Data
  std::array<uint8_t, ascon_aead128::KEY_BYTE_LEN> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  std::array<uint8_t, ascon_aead128::NONCE_BYTE_LEN> nonce{};
  std::array<uint8_t, ascon_aead128::TAG_BYTE_LEN> tag{};

  std::array<uint8_t, 10> ad = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  std::array<uint8_t, 10> plaintext = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  std::array<uint8_t, 10> ciphertext{};

  // Encryption
  ascon_aead128::ascon_aead128_t enc_handle(key, nonce);

  assert(enc_handle.absorb_data(ad) == ascon_aead128::ascon_aead128_status_t::absorbed_data);
  assert(enc_handle.finalize_data() == ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  assert(enc_handle.encrypt_plaintext(plaintext, ciphertext) == ascon_aead128::ascon_aead128_status_t::encrypted_plaintext);
  assert(enc_handle.finalize_encrypt(tag) == ascon_aead128::ascon_aead128_status_t::finalized_encryption_phase);

  // Decryption
  std::array<uint8_t, 10> decrypted_plaintext{};

  ascon_aead128::ascon_aead128_t dec_handle(key, nonce);

  assert(dec_handle.absorb_data(ad) == ascon_aead128::ascon_aead128_status_t::absorbed_data);
  assert(dec_handle.finalize_data() == ascon_aead128::ascon_aead128_status_t::finalized_data_absorption_phase);
  assert(dec_handle.decrypt_ciphertext(ciphertext, decrypted_plaintext) == ascon_aead128::ascon_aead128_status_t::decrypted_ciphertext);  
  const bool success = dec_handle.finalize_decrypt(tag) == ascon_aead128::ascon_aead128_status_t::decryption_success_as_tag_matches;

  if (success) {
    std::cout << "Decryption successful!" << std::endl;
  } else {
    std::cout << "Decryption failed!" << std::endl;
  }

  return 0;
}
```

### Ascon-Hash256

Ascon-Hash256 computes a 256-bit (32-byte) hash for any arbitrary length (>=0) input message.

```cpp
#include "ascon/hashes/ascon_hash256.hpp"
#include <array>
#include <cassert>

int main() {
  std::array<uint8_t, 10> message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  std::array<uint8_t, 32> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  assert(hasher.absorb(message) == ascon_hash256::ascon_hash256_status_t::absorbed_data);
  assert(hasher.finalize() == ascon_hash256::ascon_hash256_status_t::finalized_data_absorption_phase);
  assert(hasher.digest(digest) == ascon_hash256::ascon_hash256_status_t::message_digest_produced);

  // digest now contains the hash
  return 0;
}
```

### Ascon-XOF128 and Ascon-CXOF128

Ascon-Xof128 and Ascon-CXOF128 are extendable output functions. XOF128 produces a variable-length output, while CXOF128 allows for customization with an application-specific string.

```cpp
#include "ascon/hashes/ascon_xof128.hpp"
#include "ascon/hashes/ascon_cxof128.hpp"
#include <array>
#include <cassert>

int main() {
  // XOF128
  std::array<uint8_t, 10> message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  std::array<uint8_t, 20> output{};

  ascon_xof128::ascon_xof128_t xof;
  assert(xof.absorb(message) == ascon_xof128::ascon_xof128_status_t::absorbed_data);
  assert(xof.finalize() == ascon_xof128::ascon_xof128_status_t::finalized_data_absorption_phase);
  assert(xof.squeeze(output) == ascon_xof128::ascon_xof128_status_t::squeezed_output);

  // CXOF128
  std::array<uint8_t, 5> customization_string = {'A', 'S', 'C', 'O', 'N'};
  std::array<uint8_t, 10> message2 = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  std::array<uint8_t, 30> output2{};

  ascon_cxof128::ascon_cxof128_t cxof;
  assert(cxof.customize(customization_string) == ascon_cxof128::ascon_cxof128_status_t::customized);
  assert(cxof.absorb(message2) == ascon_cxof128::ascon_cxof128_status_t::absorbed_data);
  assert(cxof.finalize() == ascon_cxof128::ascon_cxof128_status_t::finalized_data_absorption_phase);
  assert(cxof.squeeze(output2) == ascon_cxof128::ascon_cxof128_status_t::squeezed_output);

  return 0;
}
```

Use a C++20 compliant compiler when using this library.


### Example Programs

Several example programs demonstrating the usage of each Ascon primitive are provided in the `examples` directory. To build and run these examples, simply execute the following command from the root directory of the project:


```bash
make example -j
```

This will build and run all example programs. A sample output might look like this (note that the hexadecimal values will vary due to random data generation):

```bash
Ascon-AEAD128

Key       :	b1c9e631b35c013803e6188faa0f0aaf
Nonce     :	a06a309c0b0dab74385257e5672c1867
Data      :	0af5a7f7933fa257d305194a81466be64ddeeb35262d59a67b76fdd385745eb0
Text      :	90cdc6cab91662f5452ea0f629f185f4e0b8b91bddf94b1ec0254db4dc53ddd7444ec1cf074167f3f85719ea6b79a8f004329d441883da873ec1ecb1d592df72
Encrypted :	8094a72e01b264d989b6d75e0901d2ee932602afaaba5116154d5ea278f6f322a776a8815be7afde77519ac7812cd71efbab23831918b40c223be54793b6fde2
Decrypted :	90cdc6cab91662f5452ea0f629f185f4e0b8b91bddf94b1ec0254db4dc53ddd7444ec1cf074167f3f85719ea6b79a8f004329d441883da873ec1ecb1d592df72


Ascon-Hash256

Message :	1c9a3592780c62e4c8cc8c2facaa4f74b6715ff33a58fd64a2216150a6a06d84df752381db67acb80d75e1374616279be3840e3a1f130222ecebcee8328ac997
Digest  :	02da70ac9a9e253d6d6abda26b8023c6d982f188a70f381a04ebcef1f1c7e532


Ascon-XOF128

Message :	de513722ba5d1b21c9249fd375c63785725940624ac2aa6f586fe62e7f17501a0f858e67a4c0927acd01c7476b2ac52c140d6d9167ec7832672f737c5828ab7e
Digest  :	da3c497a250cc889f66723eae9527184822308804ab20ad0a6d5a3652b713d2083a3699b6ed49be6b9fe38d438d0b2f13ad0f5378c5a2b3506966f9b2378bd19
```
