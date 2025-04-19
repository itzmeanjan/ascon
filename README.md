# ascon
Ascon-Based Lightweight Cryptography Standards for Constrained Devices: Authenticated Encryption, Hash, and Extendable Output Functions.

## Overview
This header-only C++ library implements the whole Ascon LwC cipher-suite, specifically Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128.  These algorithms, suitable for constrained environments, are part of the Ascon family designed for resource-limited devices, prioritizing security, performance, and efficiency. The library offers `constexpr` functions where possible for enhanced performance and simplifies integration.  The implementation conforms to the Ascon draft standard defined in [NIST SP 800-232](https://doi.org/10.6028/NIST.SP.800-232.ipd).

The library includes the following core Ascon cryptographic primitives:

* **Ascon-AEAD128:** Offers AEAD, encrypting the plaintext and authenticating both the ciphertext and associated data to ensure confidentiality and authenticity.
* **Ascon-Hash256:** A cryptographic hash function generating a 256-bit digest for data integrity verification and other cryptographic applications.
* **Ascon-XOF128:** An extendable output function (XOF) that produces variable-length outputs, useful in various cryptographic contexts where flexibility in output length is required.
* **Ascon-CXOF128:** A customizable XOF variant, offering additional flexibility by allowing for application-specific parameterization through a customization string.

This implementation leverages a sponge construction built upon the Ascon permutation. It employs `std::span` for safe memory handling and provides `constexpr` functions where feasible for optimized compile-time computations for statically known inputs.

**Key Features:**
* **Header-Only:** Simple integration; no linking required.
* **`constexpr` Support:** Compile-time evaluation for optimized performance where applicable.
* **`std::span` Usage:** Type-safe memory management.
* **Thorough Testing:** Includes property based tests and known-answer tests (KATs).
* **Benchmarking Support:** Prepared for benchmarking with Google Benchmark.

**Important Considerations:**
* **Unaudited:** This implementation has not yet undergone formal security audits. Production use requires careful consideration of the risks.
* **Associated Data (AEAD):** Associated data in Ascon-AEAD128 is authenticated but *not* encrypted.  Confidentiality is provided only for the plaintext.
* **Implementation Size:** While header-only, the actual size will depend on compiler optimizations and included features.

## Prerequisites

* A C++20-compliant compiler (e.g., g++, clang++).
* Build tools: `make` and `cmake`.
* For testing: Google Test ([Installation Instructions](https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project)).
* For benchmarking: Google Benchmark ([Installation Instructions](https://github.com/google/benchmark/#installation)).
* (Optional) For CPU cycle benchmarking: libPFM ([Installation Instructions](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7)). Requires building Google Benchmark with libPFM support.

## Testing

This project includes a comprehensive test suite verifying the functional correctness of Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128.  Known Answer Tests (KATs) ensure conformance to the specification.

Run tests using these commands (from the repository root):

```bash
make test -j               # Run release build tests
make debug_asan_test -j    # Run debug tests with AddressSanitizer (memory error detection)
make release_asan_test -j  # Run release tests with AddressSanitizer
make debug_ubsan_test -j   # Run debug tests with UndefinedBehaviorSanitizer
make release_ubsan_test -j # Run release tests with UndefinedBehaviorSanitizer
```

Test results (pass/fail) are printed to the console.

```bash
PASSED TESTS (37/37):
       1 ms: build/test/test.out AsconAEAD128.ValidEncryptionSequence
       1 ms: build/test/test.out AsconAEAD128.FinalizeDataCalledTwice
       1 ms: build/test/test.out AsconAEAD128.DecryptCiphertextAfterFinalizeDecrypt
       1 ms: build/test/test.out AsconXof128.CompileTimeComputeXofOutput
       1 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterFinalizeData
       1 ms: build/test/test.out AsconAEAD128.DecryptCiphertextBeforeFinalizeData
       1 ms: build/test/test.out AsconAEAD128.FinalizeDecryptBeforeFinalizeData
       1 ms: build/test/test.out AsconAEAD128.EncryptPlaintextAfterFinalizeEncrypt
       1 ms: build/test/test.out AsconAEAD128.FinalizeDecryptCalledTwice
       1 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterEncrypt
       1 ms: build/test/test.out AsconAEAD128.AbsorbDataAfterDecrypt
       1 ms: build/test/test.out AsconHash256.CompileTimeComputeMessageDigest
       2 ms: build/test/test.out AsconAEAD128.MultipleDecryptCiphertextCalls
       2 ms: build/test/test.out AsconAEAD128.MultipleAbsorbDataCalls
       2 ms: build/test/test.out AsconAEAD128.MultipleEncryptPlaintextCalls
       2 ms: build/test/test.out AsconAEAD128.FinalizeDataWithoutAbsorb
       2 ms: build/test/test.out AsconAEAD128.EncryptPlaintextBeforeFinalizeData
       2 ms: build/test/test.out AsconCXOF128.CompileTimeComputeXofOutput
       2 ms: build/test/test.out AsconAEAD128.CompileTimeEncryptAndThenDecrypt
       2 ms: build/test/test.out AsconAEAD128.FinalizeEncryptBeforeFinalizeData
       2 ms: build/test/test.out AsconAEAD128.FinalizeEncryptCalledTwice
       3 ms: build/test/test.out AsconAEAD128.ValidDecryptionSequence
       4 ms: build/test/test.out AsconAEAD128.KnownAnswerTests
       4 ms: build/test/test.out AsconCXOF128.KnownAnswerTests
       7 ms: build/test/test.out AsconHash256.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameDigest
       9 ms: build/test/test.out AsconHash256.KnownAnswerTests
      10 ms: build/test/test.out AsconXof128.KnownAnswerTests
     557 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInCipherText
     557 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInNonce
     558 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInTag
     558 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInKey
     559 ms: build/test/test.out AsconAEAD128.DecryptionFailureDueToBitFlippingInAssociatedData
     565 ms: build/test/test.out AsconAEAD128.ForSameCiphertextOneshotDecryptionAndIncrementalDecryptionProducesSamePlaintext
     566 ms: build/test/test.out AsconAEAD128.EncryptThenDecrypt
     566 ms: build/test/test.out AsconAEAD128.ForSamePlaintextOneshotEncryptionAndIncrementalEncryptionProducesSameTag
     737 ms: build/test/test.out AsconXof128.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput
    3203 ms: build/test/test.out AsconCXOF128.ForSameMessageOneshotHashingAndIncrementalHashingProducesSameOutput
```

> [!NOTE]
> There is a help menu, which introduces you to all available commands; just run `make` from the root directory of this project.

## Benchmarking

This section details how to benchmark the performance of the implemented Ascon algorithms. The benchmarks measure throughput (bytes per second) and, optionally, cycles per byte if libPFM is used.

The Makefile provides two benchmarking targets:

* **`make benchmark`:** Runs benchmarks without libPFM-based CPU cycle counting. This is the faster option and suitable for initial performance assessments.
* **`make perf`:** Runs benchmarks *with* libPFM support, providing detailed CPU cycle counts alongside throughput.  This requires building Google Benchmark with libPFM support; see the Prerequisites section for more details.

To run the benchmarks, execute the following commands from the repository root:

```bash
make benchmark -j  # Run benchmarks without CPU cycle counting
make perf -j       # Run benchmarks with CPU cycle counting (requires libPFM)
```

> [!CAUTION]
> Ensure that you've disabled CPU frequency scaling, when benchmarking, following this guide @ https://github.com/google/benchmark/blob/main/docs/reducing_variance.md.

### On 12th Gen Intel(R) Core(TM) i7-1260P

JSON benchmark result lives in [bench_result_on_Linux_6.14.0-15-generic_x86_64_with_g++_14](./bench_result_on_Linux_6.14.0-15-generic_x86_64_with_g++_14.json).

### On ARM Cortex-A72 ( i.e. Raspberry Pi 4B )

JSON benchmark result lives in [bench_result_on_Linux_6.6.62+rpt-rpi-v8_aarch64_with_g++_12](./bench_result_on_Linux_6.6.62+rpt-rpi-v8_aarch64_with_g++_12.json).

## Usage

This section demonstrates how to use the Ascon header-only library for authenticated encryption (AEAD), hashing, and extendable output functions (XOFs).  Remember that this implementation is **unaudited**, and production use requires careful consideration of the risks. No linking is required; simply include the necessary header files.

### Ascon-AEAD128

Ascon-AEAD128 provides authenticated encryption with associated data. The associated data is authenticated but not encrypted.

```cpp
#include "ascon/aead/ascon_aead128.hpp"
#include <array>
#include <iostream>

int main() {
  // Key, Nonce, and Associated Data
  std::array<uint8_t, 16> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  std::array<uint8_t, 16> nonce = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::array<uint8_t, 10> ad = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  std::array<uint8_t, 10> plaintext = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  std::array<uint8_t, 10> ciphertext{};
  std::array<uint8_t, 16> tag{};

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

Ascon-Hash256 computes a 256-bit (32-byte) hash.

```cpp
#include "ascon/hashes/ascon_hash256.hpp"
#include <array>
#include <cassert>

int main() {
  std::array<uint8_t, 10> message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  std::array<uint8_t, 32> digest{};

  ascon_hash256::ascon_hash256_t hasher;
  assert(hasher.absorb(message));
  assert(hasher.finalize());
  assert(hasher.digest(digest));

  // digest now contains the hash
  return 0;
}
```

### Ascon-XOF128 and Ascon-CXOF128

Ascon-XOF128 and Ascon-CXOF128 are extendable output functions. XOF128 produces a variable-length output, while CXOF128 allows for customization with an application-specific string.

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
  assert(xof.absorb(message));
  assert(xof.finalize());
  assert(xof.squeeze(output));

  // CXOF128
  std::array<uint8_t, 5> customization_string = {'A', 'S', 'C', 'O', 'N'};
  std::array<uint8_t, 10> message2 = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  std::array<uint8_t, 30> output2{};

  ascon_cxof128::ascon_cxof128_t cxof;
  assert(cxof.customize(customization_string));
  assert(cxof.absorb(message2));
  assert(cxof.finalize());
  assert(cxof.squeeze(output2));

  return 0;
}
```

Remember to compile with a C++20 compliant compiler.


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
