> **Warning** This implementation attempts to provide you with constant-timeness though it is not yet audited. If you consider using it in production, be careful !

# ascon
Accelerated Ascon Cipher Suite: Light Weight Cryptography

## Overview

`ascon` cipher suite is selected by NIST as winner of the **L**ight **W**eight **C**ryptography standardization effort and it's being standardized at the time of writing. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this header-only C++ library.

Scheme | What does it do ? | Comments
:-- | :-: | --:
Ascon-128 AEAD | Given 16B key, 16B nonce, N -bytes associated data and M -bytes plain text, encryption routine can be used for computing 16B authentication tag and M -bytes cipher text. While decryption algorithm can be used for decrypting cipher text, producing equal length plain text, given key, nonce, associated data ( if any ) and authentication tag. It only releases plain text if tag can be verified, in constant-time. | Primary AEAD candidate.
Ascon-128A AEAD | Same as above. | Secondary AEAD candidate, though executes faster due to higher RATE.
Ascon-80pq AEAD | Same as above, only difference is that it uses 20 -bytes secret key. | Post-quantum AEAD candidate, because it has key length of 160 -bits.
Ascon-Hash | Given N -bytes input message, hasher can be used for producing 32 -bytes digest. | Primary hash function candidate.
Ascon-HashA | Same as above. | Secondary hash function candidate, faster because it has smaller number of permutation rounds.
Ascon-XOF | Given N -bytes input message, hasher can be used for squeezing arbitrary many digest bytes. | Primary extendable output function candidate.
Ascon-XOFA | Same as above. | Secondary extendable output function candidate, faster because it has smaller number of permutation rounds.
Ascon-PRF | Given 16 -bytes key and N -bytes input message, this routine can be used for squeezing arbitrary many tag bytes. | Pseudo-random function for arbitrary length messages, proposed in https://ia.cr/2021/1574.
Ascon-MAC | Given 16 -bytes key and N -bytes input message, this routine can be used for computing 16 -bytes tag, during authentication phase. While during verification, received tag can be verified by locally computing 16 -bytes tag and comparing it constant-time. | Messaege authentication code function proposed in https://ia.cr/2021/1574, built using Ascon-PRF.
Ascon-PRFShort | Given 16 -bytes key and <= 16 -bytes input message, to be authenticated, this routine can be used for computing a <= 16 -bytes authentication tag. This PRF scheme can be used for building a message authentication code algorithm for short input messages. | Pseudo-random function for short input messages, proposed in https://ia.cr/2021/1574.

> **Note** Ascon-{Hash, HashA, Xof, XofA} supports incremental message absorption. If all message bytes are not ready to be absorbed into hash state in a single go, one can absorb messages as they become available. One may invoke absorb routine as many times necessary, until state is finalized and ready to be squeezed.

> **Note** Ascon Permutation-based hashing schemes are all `constexpr` functions - meaning one can evaluate Ascon-{Hash, HashA, Xof, XofA} on statically defined input message, during program compilation time itself. Read more about C++ `constexpr` functions @ https://en.cppreference.com/w/cpp/language/constexpr. See [usage](#usage) section below.

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Warning** Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and cipher text.

> **Note** Ascon based psuedo-random function and message authentication code scheme i.e. Ascon-PRF and Ascon-MAC respectively, support incremental message absorption/ authentication and squeezing.

> **Note** I've followed Ascon [specification](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf) and another follow-up [paper](https://eprint.iacr.org/2021/1574.pdf), describing Ascon based authentication schemes, while working on this library implementation. I suggest you also go through these specifications to better understand Ascon cipher suite.

## Prerequisites

- C++ compiler, with C++20 standard library, `g++`/ `clang++`.

```bash
$ clang++ --version
Ubuntu clang version 16.0.0 (1~exp5ubuntu3)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin

$ g++ --version
g++ (Ubuntu 13.1.0-2ubuntu2~23.04) 13.1.0
```

- Build tools such as `make`, `cmake`.

```bash
$ make -v
GNU Make 4.3

$ cmake  --version
cmake version 3.25.1
```

- `subtle` is a ( git submodule -based ) dependency of this project - used for constant-time authentication tag comparison and setting memory locations of plain text to zero bytes, in case of authentication failure. Import `subtle` by enabling git submodule in this project.

```bash
# Assuming you've already cloned https://github.com/itzmeanjan/ascon

pushd ascon
git submodule update --init
popd
```

- For testing this library implementation of Ascon cipher suite, you need to globally install `google-test` library and headers. Follow [this](https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project) guide if you don't have it installed.
- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed - ensure it's globally installed; follow [this](https://github.com/google/benchmark/#installation) guide.
- **Note:** If you are on a machine running GNU/Linux kernel and you want to obtain following (see list below), for Ascon based constructions, you should consider building google-benchmark library with libPFM support, following [this](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7) step-by-step guide. Find more about libPFM @ https://perfmon2.sourceforge.net.
    1) CPU cycle count.
    2) Retired instruction count.
    3) Cycles/ byte ( aka cpb ).
    4) Retired instructions/ cycle ( aka ipc ).

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification.

- Ensure functional correctness of Ascon AEAD, hashing and authentication schemes for various combination of inputs.
- Assess whether this implementation of Ascon cipher suite is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found inside [kats](./kats/) directory. These KAT files are originally taken from Ascon reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

```bash
make -j
```

```bash
[==========] Running 25 tests from 4 test suites.
[----------] Global test environment set-up.
[----------] 6 tests from AsconAEAD
[ RUN      ] AsconAEAD.CorrectnessTestAscon128AEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128AEAD (75 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128AEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128AEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon128aAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128aAEAD (72 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128aAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128aAEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon80pqAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon80pqAEAD (75 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD (0 ms)
[----------] 6 tests from AsconAEAD (226 ms total)

[----------] 12 tests from AsconHashing
[ RUN      ] AsconHashing.CompileTimeEvalAsconHash
[       OK ] AsconHashing.CompileTimeEvalAsconHash (0 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHash
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHash (8 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHash
[       OK ] AsconHashing.KnownAnswerTestsAsconHash (3 ms)
[ RUN      ] AsconHashing.CompileTimeEvalAsconHashA
[       OK ] AsconHashing.CompileTimeEvalAsconHashA (0 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHashA
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHashA (6 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHashA
[       OK ] AsconHashing.KnownAnswerTestsAsconHashA (2 ms)
[ RUN      ] AsconHashing.CompileTimeEvalAsconXof
[       OK ] AsconHashing.CompileTimeEvalAsconXof (0 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof (2273 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXof
[       OK ] AsconHashing.KnownAnswerTestsAsconXof (3 ms)
[ RUN      ] AsconHashing.CompileTimeEvalAsconXofA
[       OK ] AsconHashing.CompileTimeEvalAsconXofA (0 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA (1788 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXofA
[       OK ] AsconHashing.KnownAnswerTestsAsconXofA (2 ms)
[----------] 12 tests from AsconHashing (4090 ms total)

[----------] 3 tests from AsconAuth
[ RUN      ] AsconAuth.KnownAnswerTestsAsconMac
[       OK ] AsconAuth.KnownAnswerTestsAsconMac (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRF
[       OK ] AsconAuth.KnownAnswerTestsAsconPRF (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRFShort
[       OK ] AsconAuth.KnownAnswerTestsAsconPRFShort (0 ms)
[----------] 3 tests from AsconAuth (3 ms total)

[----------] 4 tests from AsconPermutation
[ RUN      ] AsconPermutation.AsconPermWithAsconHashIV
[       OK ] AsconPermutation.AsconPermWithAsconHashIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconHashAIV
[       OK ] AsconPermutation.AsconPermWithAsconHashAIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconXofIV
[       OK ] AsconPermutation.AsconPermWithAsconXofIV (0 ms)
[ RUN      ] AsconPermutation.AsconPermWithAsconXofAIV
[       OK ] AsconPermutation.AsconPermWithAsconXofAIV (0 ms)
[----------] 4 tests from AsconPermutation (0 ms total)

[----------] Global test environment tear-down
[==========] 25 tests from 4 test suites ran. (4320 ms total)
[  PASSED  ] 25 tests.
```

## Benchmarking

For benchmarking routines of Ascon lightweight cipher suite, using `google-benchmark` library as benchmark harness, while targeting CPU systems, with variable length input data, one may issue following commands.

```bash
make benchmark -j # If you haven't built google-benchmark library with libPFM support.
make perf -j      # Must do if your google-benchmark library is built with libPFM support.
```

Following routines are benchmarked

- Ascon Permutation
- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA
- Ascon-XOF
- Ascon-XOFA
- Ascon-PRF
- Ascon-MAC ( authenticate/ verify )
- Ascon-PRFShort ( authenticate/ verify )

> **Note** Benchmark recipe expects presence of `google-benchmark` header and library in `$PATH` ( so that it can be found by the compiler ).

> **Warning** Ensure that you've disabled CPU frequency scaling, when benchmarking routines, following [this](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) guide.

> **Note** `make perf -j` - was issued when collecting following benchmark statistics. Notice, columns such as *cycles*, *cycles/ byte*, *instructions* and *instructions/ cycle*. Follow [this](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) for more details.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with Clang-16.0.0 )

```bash
2023-10-03T15:22:08+05:30
Running ./build/perfs/perf.out
Run on (16 X 2500 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.38, 0.45, 0.46
----------------------------------------------------------------------------------------------------------------------------------------------------------
Benchmark                                      Time             CPU   Iterations     CYCLES CYCLES/ BYTE INSTRUCTIONS INSTRUCTIONS/ CYCLE bytes_per_second
----------------------------------------------------------------------------------------------------------------------------------------------------------
ascon_mac_verify/512_mean                    722 ns          722 ns            8   3.27953k      6.02855       11.18k             3.40904      718.809Mi/s
ascon_mac_verify/512_median                  728 ns          728 ns            8   3.27575k       6.0216       11.18k             3.41296      712.679Mi/s
ascon_mac_verify/512_stddev                 16.1 ns         16.1 ns            8    6.94449    0.0127656      226.03u            7.20528m      16.1742Mi/s
ascon_mac_verify/512_cv                     2.24 %          2.24 %             8      0.21%        0.21%        0.00%               0.21%            2.25%
ascon_mac_verify/1024_mean                  1333 ns         1333 ns            8   6.10774k      5.78385       20.62k             3.37617      755.768Mi/s
ascon_mac_verify/1024_median                1318 ns         1318 ns            8   6.11112k      5.78704       20.62k             3.37418       764.32Mi/s
ascon_mac_verify/1024_stddev                29.6 ns         29.6 ns            8    40.0692    0.0379443     260.997u           0.0223061      16.5787Mi/s
ascon_mac_verify/1024_cv                    2.22 %          2.22 %             8      0.66%        0.66%        0.00%               0.66%            2.19%
ascon80pq_aead_encrypt/256/32_mean          1024 ns         1024 ns            8   4.78402k      16.6112      12.084k             2.52591      268.154Mi/s
ascon80pq_aead_encrypt/256/32_median        1024 ns         1024 ns            8   4.78434k      16.6123      12.084k             2.52574      268.273Mi/s
ascon80pq_aead_encrypt/256/32_stddev        1.81 ns         1.80 ns            8    0.95414     3.31299m            0            503.817u      483.559Ki/s
ascon80pq_aead_encrypt/256/32_cv            0.18 %          0.18 %             8      0.02%        0.02%        0.00%               0.02%            0.18%
ascon_xofa/512/64_mean                      1867 ns         1867 ns            8    8.3434k      14.4851      29.929k             3.58715      294.496Mi/s
ascon_xofa/512/64_median                    1889 ns         1889 ns            8   8.34256k      14.4836      29.929k             3.58751      290.803Mi/s
ascon_xofa/512/64_stddev                    51.5 ns         51.5 ns            8    8.84461    0.0153552            0            3.80177m      8.33169Mi/s
ascon_xofa/512/64_cv                        2.76 %          2.76 %             8      0.11%        0.11%        0.00%               0.11%            2.83%
ascon_prf/64/64_mean                         300 ns          300 ns            8   1.36778k      10.6858       4.595k             3.35948      406.514Mi/s
ascon_prf/64/64_median                       303 ns          303 ns            8   1.36891k      10.6946       4.595k             3.35668      402.957Mi/s
ascon_prf/64/64_stddev                      5.71 ns         5.69 ns            8    3.74051    0.0292227            0            9.20776m      7.76252Mi/s
ascon_prf/64/64_cv                          1.90 %          1.90 %             8      0.27%        0.27%        0.00%               0.27%            1.91%
ascon_prf/128/16_mean                        263 ns          263 ns            8   1.20581k       8.3737       4.113k             3.41098        521.8Mi/s
ascon_prf/128/16_median                      261 ns          261 ns            8   1.20539k      8.37073       4.113k             3.41219      526.118Mi/s
ascon_prf/128/16_stddev                     5.90 ns         5.91 ns            8    1.28728     8.93942m     92.2765u            3.63638m      11.6103Mi/s
ascon_prf/128/16_cv                         2.24 %          2.24 %             8      0.11%        0.11%        0.00%               0.11%            2.23%
ascon_mac_verify/128_mean                    269 ns          269 ns            8   1.21241k      7.57758         4.1k             3.38169      567.001Mi/s
ascon_mac_verify/128_median                  270 ns          270 ns            8   1.21226k       7.5766         4.1k             3.38212      564.265Mi/s
ascon_mac_verify/128_stddev                 4.36 ns         4.36 ns            8    1.54156     9.63474m            0            4.29861m       9.3874Mi/s
ascon_mac_verify/128_cv                     1.62 %          1.62 %             8      0.13%        0.13%        0.00%               0.13%            1.66%
ascon128_aead_encrypt/2048/32_mean          6678 ns         6677 ns            8   31.1177k      14.9604      76.558k             2.46027       297.07Mi/s
ascon128_aead_encrypt/2048/32_median        6670 ns         6669 ns            8   31.1152k      14.9592      76.558k             2.46047       297.43Mi/s
ascon128_aead_encrypt/2048/32_stddev        19.3 ns         19.3 ns            8    17.1549     8.24757m            0            1.35598m      878.462Ki/s
ascon128_aead_encrypt/2048/32_cv            0.29 %          0.29 %             8      0.06%        0.06%        0.00%               0.06%            0.29%
ascon_prf/128/32_mean                        303 ns          303 ns            8   1.37505k      8.59407       4.667k             3.39406      504.255Mi/s
ascon_prf/128/32_median                      305 ns          305 ns            8   1.37468k      8.59172       4.667k             3.39498      500.655Mi/s
ascon_prf/128/32_stddev                     7.00 ns         7.00 ns            8    1.71264     0.010704     65.2493u             4.2228m      11.7217Mi/s
ascon_prf/128/32_cv                         2.31 %          2.31 %             8      0.12%        0.12%        0.00%               0.12%            2.32%
ascon_prfs_verify/1_mean                    53.6 ns         53.6 ns            8    249.322       14.666          681             2.73141      302.698Mi/s
ascon_prfs_verify/1_median                  53.5 ns         53.5 ns            8    249.446      14.6733          681             2.73005      303.153Mi/s
ascon_prfs_verify/1_stddev                 0.318 ns        0.318 ns            8   0.203707    0.0119828     8.15617u            2.23261m      1.79096Mi/s
ascon_prfs_verify/1_cv                      0.59 %          0.59 %             8      0.08%        0.08%        0.00%               0.08%            0.59%
ascon80pq_aead_encrypt/2048/32_mean         6674 ns         6674 ns            8   31.1189k       14.961      76.596k              2.4614      297.226Mi/s
ascon80pq_aead_encrypt/2048/32_median       6671 ns         6670 ns            8   31.1195k      14.9613      76.596k             2.46135      297.396Mi/s
ascon80pq_aead_encrypt/2048/32_stddev       22.8 ns         22.7 ns            8    18.7733     9.02563m            0            1.48459m      1.00819Mi/s
ascon80pq_aead_encrypt/2048/32_cv           0.34 %          0.34 %             8      0.06%        0.06%        0.00%               0.06%            0.34%
ascon80pq_aead_decrypt/2048/32_mean         6621 ns         6621 ns            8   30.8454k      14.8295      77.409k             2.50958      299.623Mi/s
ascon80pq_aead_decrypt/2048/32_median       6615 ns         6614 ns            8   30.8351k      14.8246      77.409k             2.51042      299.914Mi/s
ascon80pq_aead_decrypt/2048/32_stddev       23.9 ns         23.9 ns            8    28.7211    0.0138082            0            2.33582m       1.0793Mi/s
ascon80pq_aead_decrypt/2048/32_cv           0.36 %          0.36 %             8      0.09%        0.09%        0.00%               0.09%            0.36%
ascon128_aead_decrypt/512/32_mean           1821 ns         1820 ns            8   8.49966k      15.6244      21.523k             2.53222      284.983Mi/s
ascon128_aead_decrypt/512/32_median         1819 ns         1819 ns            8   8.49969k      15.6244      21.523k             2.53221      285.224Mi/s
ascon128_aead_decrypt/512/32_stddev         6.00 ns         6.00 ns            8    1.14449     2.10384m     452.061u            340.966u      957.709Ki/s
ascon128_aead_decrypt/512/32_cv             0.33 %          0.33 %             8      0.01%        0.01%        0.00%               0.01%            0.33%
ascon80pq_aead_decrypt/128/32_mean           625 ns          625 ns            8   2.91583k      18.2239       7.599k             2.60612      244.152Mi/s
ascon80pq_aead_decrypt/128/32_median         625 ns          625 ns            8   2.91575k      18.2234       7.599k             2.60619       244.23Mi/s
ascon80pq_aead_decrypt/128/32_stddev        1.86 ns         1.85 ns            8   0.626848      3.9178m            0            560.185u      740.521Ki/s
ascon80pq_aead_decrypt/128/32_cv            0.30 %          0.30 %             8      0.02%        0.02%        0.00%               0.02%            0.30%
ascon128_aead_decrypt/4096/32_mean         13020 ns        13019 ns            8    60.739k      14.7139     151.835k              2.4998      302.383Mi/s
ascon128_aead_decrypt/4096/32_median       13002 ns        13001 ns            8    60.741k      14.7144     151.835k             2.49971      302.802Mi/s
ascon128_aead_decrypt/4096/32_stddev        45.3 ns         45.4 ns            8    38.7569     9.38878m            0             1.5949m      1.04772Mi/s
ascon128_aead_decrypt/4096/32_cv            0.35 %          0.35 %             8      0.06%        0.06%        0.00%               0.06%            0.35%
ascon_hash/4096_mean                       19488 ns        19486 ns            8   86.3425k      20.9163     301.548k             3.49246      202.034Mi/s
ascon_hash/4096_median                     19508 ns        19505 ns            8   86.5676k      20.9708     302.357k             3.49269      201.838Mi/s
ascon_hash/4096_stddev                       127 ns          127 ns            8    662.374     0.160459     2.28976k            1.06385m      1.31734Mi/s
ascon_hash/4096_cv                          0.65 %          0.65 %             8      0.77%        0.77%        0.76%               0.03%            0.65%
ascon_xofa/4096/32_mean                    13102 ns        13101 ns            8   58.3781k       14.142     211.601k             3.62467      300.843Mi/s
ascon_xofa/4096/32_median                  13372 ns        13371 ns            8   58.3483k      14.1348     211.601k             3.62652      294.431Mi/s
ascon_xofa/4096/32_stddev                    476 ns          476 ns            8    73.7804    0.0178732            0             4.5722m      11.1196Mi/s
ascon_xofa/4096/32_cv                       3.63 %          3.63 %             8      0.13%        0.13%        0.00%               0.13%            3.70%
ascon80pq_aead_encrypt/128/32_mean           621 ns          621 ns            8   2.89799k      18.1125       7.476k             2.57972      245.569Mi/s
ascon80pq_aead_encrypt/128/32_median         621 ns          621 ns            8   2.89791k      18.1119       7.476k             2.57979      245.771Mi/s
ascon80pq_aead_encrypt/128/32_stddev        2.17 ns         2.17 ns            8   0.506901     3.16813m     92.2765u            451.186u      874.429Ki/s
ascon80pq_aead_encrypt/128/32_cv            0.35 %          0.35 %             8      0.02%        0.02%        0.00%               0.02%            0.35%
ascon_prf/1024/32_mean                      1386 ns         1386 ns            8     6.246k      5.91478      21.187k             3.39227      726.903Mi/s
ascon_prf/1024/32_median                    1394 ns         1394 ns            8   6.27767k      5.94476      21.187k             3.37498      722.425Mi/s
ascon_prf/1024/32_stddev                    26.3 ns         26.3 ns            8    48.8602    0.0462691            0           0.0266361      14.0187Mi/s
ascon_prf/1024/32_cv                        1.90 %          1.90 %             8      0.78%        0.78%        0.00%               0.79%            1.93%
ascon_mac_verify/2048_mean                  2575 ns         2575 ns            8   11.6578k      5.60472        39.5k              3.3885      770.597Mi/s
ascon_mac_verify/2048_median                2603 ns         2603 ns            8   11.6847k      5.61765        39.5k             3.38049      762.106Mi/s
ascon_mac_verify/2048_stddev                53.9 ns         53.8 ns            8    98.0834    0.0471555     904.121u           0.0287191      16.2244Mi/s
ascon_mac_verify/2048_cv                    2.09 %          2.09 %             8      0.84%        0.84%        0.00%               0.85%            2.11%
ascon_xofa/64/32_mean                        343 ns          343 ns            8   1.52287k      15.8632       5.465k             3.58863      267.119Mi/s
ascon_xofa/64/32_median                      347 ns          347 ns            8   1.52238k      15.8581       5.465k             3.58979      263.941Mi/s
ascon_xofa/64/32_stddev                     9.75 ns         9.76 ns            8    1.71194    0.0178327            0            4.03036m      7.81949Mi/s
ascon_xofa/64/32_cv                         2.84 %          2.85 %             8      0.11%        0.11%        0.00%               0.11%            2.93%
ascon128a_aead_decrypt/512/32_mean          1101 ns         1101 ns            8   4.95727k      9.11263      16.501k             3.32865        471.4Mi/s
ascon128a_aead_decrypt/512/32_median        1111 ns         1110 ns            8    4.9575k      9.11306      16.501k             3.32849      467.195Mi/s
ascon128a_aead_decrypt/512/32_stddev        19.2 ns         19.2 ns            8    2.36278     4.34335m            0            1.58685m      8.36201Mi/s
ascon128a_aead_decrypt/512/32_cv            1.75 %          1.75 %             8      0.05%        0.05%        0.00%               0.05%            1.77%
ascon_prfs_authenticate/1_mean              50.8 ns         50.8 ns            8    236.022      13.8836          669             2.83449      319.071Mi/s
ascon_prfs_authenticate/1_median            50.8 ns         50.8 ns            8    236.043      13.8849          669             2.83423      319.234Mi/s
ascon_prfs_authenticate/1_stddev           0.233 ns        0.233 ns            8   0.159863     9.40368m     8.15617u            1.91948m      1.45598Mi/s
ascon_prfs_authenticate/1_cv                0.46 %          0.46 %             8      0.07%        0.07%        0.00%               0.07%            0.46%
ascon_xof/2048/64_mean                      9825 ns         9824 ns            8   44.4241k      21.0341     154.857k             3.48589      205.138Mi/s
ascon_xof/2048/64_median                    9914 ns         9914 ns            8   44.4265k      21.0353     154.857k             3.48569      203.164Mi/s
ascon_xof/2048/64_stddev                     256 ns          256 ns            8    56.3647    0.0266878     2.08798m            4.41934m      5.39797Mi/s
ascon_xof/2048/64_cv                        2.61 %          2.61 %             8      0.13%        0.13%        0.00%               0.13%            2.63%
ascon_xof/1024/32_mean                      4902 ns         4902 ns            8   22.2551k      21.0749      77.745k             3.49335      205.614Mi/s
ascon_xof/1024/32_median                    4877 ns         4876 ns            8   22.2528k      21.0727      77.745k             3.49372      206.618Mi/s
ascon_xof/1024/32_stddev                     147 ns          147 ns            8    8.13577     7.70433m     1.04399m             1.2764m      6.12224Mi/s
ascon_xof/1024/32_cv                        2.99 %          2.99 %             8      0.04%        0.04%        0.00%               0.04%            2.98%
ascon_prf/4096/64_mean                      5121 ns         5121 ns            8   23.1433k       5.5633      78.935k             3.41087      775.212Mi/s
ascon_prf/4096/64_median                    5174 ns         5174 ns            8   23.0335k      5.53689      78.935k             3.42697      766.834Mi/s
ascon_prf/4096/64_stddev                     132 ns          132 ns            8    173.538    0.0417159     1.04399m           0.0254849      20.1371Mi/s
ascon_prf/4096/64_cv                        2.57 %          2.57 %             8      0.75%        0.75%        0.00%               0.75%            2.60%
ascon_prf/4096/16_mean                      5068 ns         5068 ns            8   22.6969k      5.51968      77.273k             3.40478      774.133Mi/s
ascon_prf/4096/16_median                    5080 ns         5080 ns            8   22.6996k      5.52033      77.273k             3.40431      771.986Mi/s
ascon_prf/4096/16_stddev                     103 ns          103 ns            8    195.126    0.0474527            0           0.0292683      15.8498Mi/s
ascon_prf/4096/16_cv                        2.02 %          2.02 %             8      0.86%        0.86%        0.00%               0.86%            2.05%
ascon_prfs_verify/8_mean                    43.8 ns         43.8 ns            8    195.963      8.16511          678             3.45987       523.07Mi/s
ascon_prfs_verify/8_median                  44.3 ns         44.3 ns            8    195.931      8.16379          678              3.4604       516.83Mi/s
ascon_prfs_verify/8_stddev                  1.06 ns         1.06 ns            8   0.625978    0.0260824     11.5346u           0.0110194      13.0077Mi/s
ascon_prfs_verify/8_cv                      2.42 %          2.42 %             8      0.32%        0.32%        0.00%               0.32%            2.49%
ascon128a_aead_encrypt/4096/32_mean         7628 ns         7627 ns            8   34.8043k      8.43128     118.048k             3.39176      516.424Mi/s
ascon128a_aead_encrypt/4096/32_median       7596 ns         7595 ns            8      34.8k      8.43024     118.048k             3.39218      518.457Mi/s
ascon128a_aead_encrypt/4096/32_stddev        195 ns          195 ns            8    16.3661     3.96466m            0            1.59445m      13.1233Mi/s
ascon128a_aead_encrypt/4096/32_cv           2.56 %          2.56 %             8      0.05%        0.05%        0.00%               0.05%            2.54%
ascon128a_aead_encrypt/2048/32_mean         3876 ns         3875 ns            8   17.7819k      8.54899       60.32k             3.39222      512.151Mi/s
ascon128a_aead_encrypt/2048/32_median       3821 ns         3821 ns            8   17.7855k      8.55072       60.32k             3.39153      519.118Mi/s
ascon128a_aead_encrypt/2048/32_stddev       97.3 ns         97.3 ns            8    9.08792     4.36919m     738.212u            1.73448m      12.5846Mi/s
ascon128a_aead_encrypt/2048/32_cv           2.51 %          2.51 %             8      0.05%        0.05%        0.00%               0.05%            2.46%
ascon_mac_authenticate/512_mean              726 ns          726 ns            8   3.27389k      6.20054      11.164k             3.41003      694.099Mi/s
ascon_mac_authenticate/512_median            733 ns          733 ns            8   3.26984k      6.19288      11.164k             3.41423      687.021Mi/s
ascon_mac_authenticate/512_stddev           19.4 ns         19.4 ns            8    7.46874    0.0141453     184.553u            7.77193m      18.7357Mi/s
ascon_mac_authenticate/512_cv               2.68 %          2.67 %             8      0.23%        0.23%        0.00%               0.23%            2.70%
ascon_prf/1024/16_mean                      1363 ns         1363 ns            8   6.06848k      5.83508      20.633k             3.40024      727.706Mi/s
ascon_prf/1024/16_median                    1363 ns         1363 ns            8   6.06673k      5.83339      20.633k             3.40118      727.858Mi/s
ascon_prf/1024/16_stddev                    7.34 ns         7.35 ns            8     50.835    0.0488798            0           0.0284804      3.91691Mi/s
ascon_prf/1024/16_cv                        0.54 %          0.54 %             8      0.84%        0.84%        0.00%               0.84%            0.54%
ascon128a_aead_encrypt/1024/32_mean         2062 ns         2062 ns            8   9.27693k      8.78497      31.456k             3.39078      488.667Mi/s
ascon128a_aead_encrypt/1024/32_median       2086 ns         2086 ns            8   9.27629k      8.78437      31.456k             3.39101      482.877Mi/s
ascon128a_aead_encrypt/1024/32_stddev       45.5 ns         45.5 ns            8    5.50904     5.21689m     521.995u            2.01293m      10.9636Mi/s
ascon128a_aead_encrypt/1024/32_cv           2.21 %          2.21 %             8      0.06%        0.06%        0.00%               0.06%            2.24%
ascon_xofa/2048/32_mean                     6715 ns         6715 ns            8   29.5012k      14.1833     106.897k             3.62348      295.572Mi/s
ascon_xofa/2048/32_median                   6746 ns         6746 ns            8   29.4994k      14.1824     106.897k              3.6237      294.043Mi/s
ascon_xofa/2048/32_stddev                    165 ns          166 ns            8    15.0961     7.25775m            0            1.85343m      7.63445Mi/s
ascon_xofa/2048/32_cv                       2.46 %          2.47 %             8      0.05%        0.05%        0.00%               0.05%            2.58%
ascon_xof/512/32_mean                       2572 ns         2571 ns            8   11.5474k      21.2268      40.305k              3.4904      201.882Mi/s
ascon_xof/512/32_median                     2590 ns         2589 ns            8   11.5466k      21.2254      40.305k             3.49063      200.363Mi/s
ascon_xof/512/32_stddev                     65.7 ns         65.7 ns            8    3.25655     5.98631m            0            983.904u      5.24932Mi/s
ascon_xof/512/32_cv                         2.55 %          2.55 %             8      0.03%        0.03%        0.00%               0.03%            2.60%
ascon_prfs_verify/2_mean                    53.8 ns         53.8 ns            8    249.816      13.8786          683             2.73402      319.321Mi/s
ascon_prfs_verify/2_median                  53.6 ns         53.6 ns            8    249.745      13.8747          683             2.73479      320.411Mi/s
ascon_prfs_verify/2_stddev                 0.395 ns        0.395 ns            8   0.222149    0.0123416            0             2.4307m      2.33111Mi/s
ascon_prfs_verify/2_cv                      0.74 %          0.74 %             8      0.09%        0.09%        0.00%               0.09%            0.73%
ascon128a_aead_decrypt/4096/32_mean         7512 ns         7512 ns            8    34.047k      8.24781     113.213k             3.32521      524.418Mi/s
ascon128a_aead_decrypt/4096/32_median       7576 ns         7575 ns            8   34.0519k      8.24902     113.213k             3.32472      519.684Mi/s
ascon128a_aead_decrypt/4096/32_stddev        200 ns          200 ns            8    41.2216     9.98586m     1.47642m            4.02639m      14.0367Mi/s
ascon128a_aead_decrypt/4096/32_cv           2.66 %          2.66 %             8      0.12%        0.12%        0.00%               0.12%            2.68%
ascon80pq_aead_decrypt/1024/32_mean         3422 ns         3421 ns            8   15.9389k      15.0936      40.177k             2.52069      294.358Mi/s
ascon80pq_aead_decrypt/1024/32_median       3417 ns         3416 ns            8   15.9398k      15.0945      40.177k             2.52055      294.777Mi/s
ascon80pq_aead_decrypt/1024/32_stddev       11.6 ns         11.6 ns            8    3.15012     2.98307m            0            498.197u      1015.31Ki/s
ascon80pq_aead_decrypt/1024/32_cv           0.34 %          0.34 %             8      0.02%        0.02%        0.00%               0.02%            0.34%
ascon128_aead_encrypt/128/32_mean            624 ns          624 ns            8   2.90399k      18.1499       7.438k             2.56131      244.653Mi/s
ascon128_aead_encrypt/128/32_median          623 ns          623 ns            8   2.90386k      18.1491       7.438k             2.56142      244.864Mi/s
ascon128_aead_encrypt/128/32_stddev         2.19 ns         2.18 ns            8   0.298418     1.86511m            0            263.182u      873.678Ki/s
ascon128_aead_encrypt/128/32_cv             0.35 %          0.35 %             8      0.01%        0.01%        0.00%               0.01%            0.35%
ascon_mac_authenticate/1024_mean            1353 ns         1353 ns            8   6.07851k      5.84472      20.604k             3.38984      733.183Mi/s
ascon_mac_authenticate/1024_median          1362 ns         1362 ns            8   6.10354k      5.86879      20.604k             3.37575      728.065Mi/s
ascon_mac_authenticate/1024_stddev          23.6 ns         23.6 ns            8    48.7925    0.0469159            0           0.0273056      12.9662Mi/s
ascon_mac_authenticate/1024_cv              1.74 %          1.74 %             8      0.80%        0.80%        0.00%               0.81%            1.77%
ascon80pq_aead_encrypt/4096/32_mean        13196 ns        13195 ns            8   61.2776k      14.8444     150.324k             2.45316      298.375Mi/s
ascon80pq_aead_encrypt/4096/32_median      13155 ns        13155 ns            8   61.2902k      14.8474     150.324k             2.45266      299.271Mi/s
ascon80pq_aead_encrypt/4096/32_stddev        136 ns          136 ns            8    36.3147     8.79717m     2.08798m            1.45431m      3.01726Mi/s
ascon80pq_aead_encrypt/4096/32_cv           1.03 %          1.03 %             8      0.06%        0.06%        0.00%               0.06%            1.01%
ascon128a_aead_encrypt/128/32_mean           408 ns          408 ns            8   1.83031k      11.4395         6.2k              3.3874      374.277Mi/s
ascon128a_aead_encrypt/128/32_median         406 ns          406 ns            8   1.83027k      11.4392         6.2k             3.38748      376.041Mi/s
ascon128a_aead_encrypt/128/32_stddev        5.01 ns         5.01 ns            8   0.282304      1.7644m     92.2765u            522.443u       4.5763Mi/s
ascon128a_aead_encrypt/128/32_cv            1.23 %          1.23 %             8      0.02%        0.02%        0.00%               0.02%            1.22%
ascon_prfs_verify/4_mean                    53.5 ns         53.5 ns            8     248.53      12.4265          680             2.73609      356.822Mi/s
ascon_prfs_verify/4_median                  53.4 ns         53.3 ns            8    248.562      12.4281          680             2.73574      357.535Mi/s
ascon_prfs_verify/4_stddev                 0.374 ns        0.375 ns            8   0.206373    0.0103187     8.15617u            2.27303m      2.48395Mi/s
ascon_prfs_verify/4_cv                      0.70 %          0.70 %             8      0.08%        0.08%        0.00%               0.08%            0.70%
ascon_prf/512/64_mean                        836 ns          836 ns            8   3.76658k      6.53921      12.855k             3.41291      657.432Mi/s
ascon_prf/512/64_median                      843 ns          843 ns            8   3.76787k      6.54143      12.855k             3.41175      651.302Mi/s
ascon_prf/512/64_stddev                     19.1 ns         19.2 ns            8    2.71807     4.71887m            0            2.46467m      15.3401Mi/s
ascon_prf/512/64_cv                         2.29 %          2.29 %             8      0.07%        0.07%        0.00%               0.07%            2.33%
ascon_prf/2048/16_mean                      2604 ns         2604 ns            8   11.5907k      5.61564      39.513k             3.40925      756.033Mi/s
ascon_prf/2048/16_median                    2596 ns         2596 ns            8   11.5321k      5.58725      39.513k             3.42635      758.166Mi/s
ascon_prf/2048/16_stddev                    38.5 ns         38.5 ns            8    99.3544    0.0481368            0           0.0291149      11.1766Mi/s
ascon_prf/2048/16_cv                        1.48 %          1.48 %             8      0.86%        0.86%        0.00%               0.85%            1.48%
ascon_xofa/256/64_mean                      1073 ns         1073 ns            8   4.73923k      14.8101      16.841k             3.55356      284.615Mi/s
ascon_xofa/256/64_median                    1082 ns         1082 ns            8   4.73947k      14.8108      16.841k             3.55335      281.965Mi/s
ascon_xofa/256/64_stddev                    28.8 ns         28.8 ns            8    14.5411    0.0454408            0           0.0109176       7.9861Mi/s
ascon_xofa/256/64_cv                        2.68 %          2.68 %             8      0.31%        0.31%        0.00%               0.31%            2.81%
ascon_mac_authenticate/4096_mean            4963 ns         4962 ns            8   22.6721k      5.51364      77.244k              3.4073      790.635Mi/s
ascon_mac_authenticate/4096_median          4923 ns         4923 ns            8   22.5516k      5.48434      77.244k             3.42522      796.619Mi/s
ascon_mac_authenticate/4096_stddev           118 ns          118 ns            8    223.575    0.0543713            0           0.0334467       18.657Mi/s
ascon_mac_authenticate/4096_cv              2.38 %          2.37 %             8      0.99%        0.99%        0.00%               0.98%            2.36%
ascon80pq_aead_decrypt/64/32_mean            428 ns          428 ns            8    1.9868k      20.6959       5.296k             2.66559      214.056Mi/s
ascon80pq_aead_decrypt/64/32_median          428 ns          428 ns            8   1.98672k      20.6951       5.296k             2.66569      214.117Mi/s
ascon80pq_aead_decrypt/64/32_stddev         2.00 ns         2.00 ns            8   0.305207     3.17924m            0            409.445u      1.00065Mi/s
ascon80pq_aead_decrypt/64/32_cv             0.47 %          0.47 %             8      0.02%        0.02%        0.00%               0.02%            0.47%
ascon_prf/64/16_mean                         191 ns          191 ns            8    870.567      10.8821       2.933k             3.36908      398.659Mi/s
ascon_prf/64/16_median                       192 ns          192 ns            8    871.253      10.8907       2.933k             3.36642      397.431Mi/s
ascon_prf/64/16_stddev                      4.23 ns         4.23 ns            8    1.99113    0.0248892     79.9138u             7.7209m      8.80118Mi/s
ascon_prf/64/16_cv                          2.21 %          2.21 %             8      0.23%        0.23%        0.00%               0.23%            2.21%
ascon_mac_authenticate/256_mean              427 ns          427 ns            8   1.91817k       7.0521       6.444k             3.35945      607.514Mi/s
ascon_mac_authenticate/256_median            430 ns          430 ns            8   1.91818k      7.05213       6.444k             3.35944      603.701Mi/s
ascon_mac_authenticate/256_stddev           6.92 ns         6.92 ns            8    2.02756     7.45427m            0            3.55292m      10.1563Mi/s
ascon_mac_authenticate/256_cv               1.62 %          1.62 %             8      0.11%        0.11%        0.00%               0.11%            1.67%
ascon_permutation<6>_mean                   24.1 ns         24.1 ns            8    112.185      2.80462          266             2.37109      1.54463Gi/s
ascon_permutation<6>_median                 24.1 ns         24.1 ns            8    112.171      2.80428          266             2.37137      1.54692Gi/s
ascon_permutation<6>_stddev                0.112 ns        0.112 ns            8  0.0306038     765.094u     4.07808u             646.71u       7.3068Mi/s
ascon_permutation<6>_cv                     0.46 %          0.46 %             8      0.03%        0.03%        0.00%               0.03%            0.46%
ascon_xofa/2048/64_mean                     6798 ns         6798 ns            8    29.984k       14.197     108.457k             3.61717      296.625Mi/s
ascon_xofa/2048/64_median                   6932 ns         6931 ns            8   29.9927k      14.2011     108.457k             3.61611      290.588Mi/s
ascon_xofa/2048/64_stddev                    238 ns          238 ns            8      26.86    0.0127178     2.08798m            3.24178m        10.77Mi/s
ascon_xofa/2048/64_cv                       3.50 %          3.50 %             8      0.09%        0.09%        0.00%               0.09%            3.63%
ascon_xofa/256/32_mean                       962 ns          962 ns            8   4.24244k      14.7307      15.281k             3.60195      285.897Mi/s
ascon_xofa/256/32_median                     974 ns          974 ns            8   4.23959k      14.7208      15.281k             3.60436      281.991Mi/s
ascon_xofa/256/32_stddev                    31.1 ns         31.0 ns            8    8.85436    0.0307443     260.997u            7.48893m      9.51515Mi/s
ascon_xofa/256/32_cv                        3.23 %          3.23 %             8      0.21%        0.21%        0.00%               0.21%            3.33%
ascon_hasha/2048_mean                       6735 ns         6734 ns            8   29.5053k      14.1852     106.869k             3.62203       294.74Mi/s
ascon_hasha/2048_median                     6779 ns         6779 ns            8   29.5047k       14.185     106.869k              3.6221       292.63Mi/s
ascon_hasha/2048_stddev                      175 ns          175 ns            8    7.30796     3.51344m            0            897.012u      8.04329Mi/s
ascon_hasha/2048_cv                         2.60 %          2.60 %             8      0.02%        0.02%        0.00%               0.02%            2.73%
ascon_xof/64/32_mean                         481 ns          481 ns            8   2.17118k      22.6165       7.545k             3.47507      190.438Mi/s
ascon_xof/64/32_median                       483 ns          483 ns            8   2.17103k      22.6149       7.545k             3.47531      189.529Mi/s
ascon_xof/64/32_stddev                      9.31 ns         9.31 ns            8    2.05001    0.0213543            0            3.28105m      3.72933Mi/s
ascon_xof/64/32_cv                          1.94 %          1.94 %             8      0.09%        0.09%        0.00%               0.09%            1.96%
ascon_hasha/256_mean                         949 ns          949 ns            8   4.23672k      14.7108      15.253k             3.60019      289.935Mi/s
ascon_hasha/256_median                       965 ns          965 ns            8    4.2366k      14.7104      15.253k             3.60029      284.581Mi/s
ascon_hasha/256_stddev                      35.9 ns         35.9 ns            8    1.88547     6.54678m     184.553u            1.60213m      11.1145Mi/s
ascon_hasha/256_cv                          3.78 %          3.78 %             8      0.04%        0.04%        0.00%               0.04%            3.83%
ascon_prf/4096/32_mean                      5123 ns         5122 ns            8   22.8609k      5.53801      77.827k             3.40461      768.766Mi/s
ascon_prf/4096/32_median                    5155 ns         5155 ns            8   22.8555k       5.5367      77.827k             3.40533       763.74Mi/s
ascon_prf/4096/32_stddev                    90.8 ns         90.7 ns            8    201.773    0.0488791     1.04399m            0.030047      13.9608Mi/s
ascon_prf/4096/32_cv                        1.77 %          1.77 %             8      0.88%        0.88%        0.00%               0.88%            1.82%
ascon_mac_authenticate/128_mean              265 ns          265 ns            8   1.20715k      8.38297       4.084k             3.38319      518.877Mi/s
ascon_mac_authenticate/128_median            267 ns          267 ns            8   1.20656k      8.37891       4.084k             3.38482      514.627Mi/s
ascon_mac_authenticate/128_stddev           5.65 ns         5.64 ns            8    1.72647    0.0119894     46.1382u            4.83122m      11.0804Mi/s
ascon_mac_authenticate/128_cv               2.13 %          2.13 %             8      0.14%        0.14%        0.00%               0.14%            2.14%
ascon_xofa/1024/32_mean                     3341 ns         3341 ns            8   15.0584k      14.2598      54.545k             3.62224        301.8Mi/s
ascon_xofa/1024/32_median                   3319 ns         3318 ns            8   15.0554k       14.257      54.545k             3.62295       303.64Mi/s
ascon_xofa/1024/32_stddev                    125 ns          125 ns            8    9.52422     9.01915m            0            2.28973m      11.2509Mi/s
ascon_xofa/1024/32_cv                       3.75 %          3.75 %             8      0.06%        0.06%        0.00%               0.06%            3.73%
ascon_prfs_authenticate/2_mean              50.9 ns         50.9 ns            8    235.983      13.1102          671             2.84343      337.164Mi/s
ascon_prfs_authenticate/2_median            50.8 ns         50.8 ns            8    236.006      13.1114          671             2.84315      337.912Mi/s
ascon_prfs_authenticate/2_stddev           0.518 ns        0.519 ns            8   0.292306    0.0162392     8.15617u            3.52253m      3.42036Mi/s
ascon_prfs_authenticate/2_cv                1.02 %          1.02 %             8      0.12%        0.12%        0.00%               0.12%            1.01%
ascon128_aead_decrypt/2048/32_mean          6616 ns         6616 ns            8    30.831k      14.8226      77.371k             2.50952       299.85Mi/s
ascon128_aead_decrypt/2048/32_median        6617 ns         6617 ns            8   30.8294k      14.8218      77.371k             2.50965      299.794Mi/s
ascon128_aead_decrypt/2048/32_stddev        22.9 ns         23.0 ns            8     20.747      9.9745m            0            1.68786m      1.04231Mi/s
ascon128_aead_decrypt/2048/32_cv            0.35 %          0.35 %             8      0.07%        0.07%        0.00%               0.07%            0.35%
ascon_mac_authenticate/2048_mean            2578 ns         2577 ns            8    11.619k      5.62934      39.484k             3.39849      764.171Mi/s
ascon_mac_authenticate/2048_median          2604 ns         2604 ns            8   11.6172k      5.62851      39.484k              3.3988      755.953Mi/s
ascon_mac_authenticate/2048_stddev          67.7 ns         67.8 ns            8    105.367    0.0510498            0           0.0307871      20.3062Mi/s
ascon_mac_authenticate/2048_cv              2.63 %          2.63 %             8      0.91%        0.91%        0.00%               0.91%            2.66%
ascon_xof/4096/32_mean                     19366 ns        19365 ns            8   86.5086k      20.9565     302.385k             3.49543      203.437Mi/s
ascon_xof/4096/32_median                   19556 ns        19555 ns            8   86.5076k      20.9563     302.385k             3.49547      201.322Mi/s
ascon_xof/4096/32_stddev                     547 ns          548 ns            8     8.0169     1.94208m            0            323.901u      5.87807Mi/s
ascon_xof/4096/32_cv                        2.83 %          2.83 %             8      0.01%        0.01%        0.00%               0.01%            2.89%
ascon_hasha/1024_mean                       3397 ns         3397 ns            8    15.062k      14.2633      54.517k             3.61951      296.758Mi/s
ascon_hasha/1024_median                     3432 ns         3431 ns            8     15.06k      14.2613      54.517k                3.62      293.482Mi/s
ascon_hasha/1024_stddev                      106 ns          106 ns            8    9.65413     9.14217m            0            2.31898m      9.51947Mi/s
ascon_hasha/1024_cv                         3.12 %          3.12 %             8      0.06%        0.06%        0.00%               0.06%            3.21%
ascon_mac_verify/256_mean                    427 ns          427 ns            8   1.92469k      6.68294        6.46k              3.3564       643.52Mi/s
ascon_mac_verify/256_median                  428 ns          428 ns            8   1.92419k      6.68122        6.46k             3.35726       641.05Mi/s
ascon_mac_verify/256_stddev                 7.90 ns         7.89 ns            8    3.20452    0.0111268     92.2765u            5.58939m      12.0249Mi/s
ascon_mac_verify/256_cv                     1.85 %          1.85 %             8      0.17%        0.17%        0.00%               0.17%            1.87%
ascon_xof/4096/64_mean                     19166 ns        19165 ns            8   87.2968k      20.9848     304.617k             3.48944      207.205Mi/s
ascon_xof/4096/64_median                   18774 ns        18773 ns            8    87.295k      20.9844     304.617k             3.48951       211.33Mi/s
ascon_xof/4096/64_stddev                     636 ns          636 ns            8    52.7204    0.0126732            0            2.10715m      6.76837Mi/s
ascon_xof/4096/64_cv                        3.32 %          3.32 %             8      0.06%        0.06%        0.00%               0.06%            3.27%
ascon_prf/256/64_mean                        538 ns          538 ns            8   2.42061k       7.5644       8.135k             3.36073      567.084Mi/s
ascon_prf/256/64_median                      538 ns          537 ns            8   2.42143k      7.56697       8.135k             3.35958      567.824Mi/s
ascon_prf/256/64_stddev                     9.50 ns         9.50 ns            8    2.70954     8.46732m            0             3.7656m      10.1923Mi/s
ascon_prf/256/64_cv                         1.77 %          1.77 %             8      0.11%        0.11%        0.00%               0.11%            1.80%
ascon128a_aead_encrypt/256/32_mean           650 ns          650 ns            8   2.90155k      10.0748       9.808k             3.38027      422.972Mi/s
ascon128a_aead_encrypt/256/32_median         651 ns          651 ns            8   2.90105k      10.0731       9.808k             3.38084      421.667Mi/s
ascon128a_aead_encrypt/256/32_stddev        11.4 ns         11.4 ns            8    2.32718      8.0805m     184.553u            2.70997m      7.57184Mi/s
ascon128a_aead_encrypt/256/32_cv            1.75 %          1.75 %             8      0.08%        0.08%        0.00%               0.08%            1.79%
ascon128_aead_encrypt/64/32_mean             421 ns          421 ns            8   1.96034k      20.4202       5.134k             2.61894      217.409Mi/s
ascon128_aead_encrypt/64/32_median           421 ns          421 ns            8   1.96032k        20.42       5.134k             2.61896      217.675Mi/s
ascon128_aead_encrypt/64/32_stddev          1.57 ns         1.58 ns            8   0.230245     2.39839m            0            307.569u      832.705Ki/s
ascon128_aead_encrypt/64/32_cv              0.37 %          0.37 %             8      0.01%        0.01%        0.00%               0.01%            0.37%
ascon128_aead_encrypt/512/32_mean           1830 ns         1830 ns            8   8.54404k       15.706      21.262k             2.48852      283.496Mi/s
ascon128_aead_encrypt/512/32_median         1829 ns         1829 ns            8   8.54358k      15.7051      21.262k             2.48865      283.606Mi/s
ascon128_aead_encrypt/512/32_stddev         3.14 ns         3.21 ns            8    1.34578     2.47387m            0            391.903u      507.442Ki/s
ascon128_aead_encrypt/512/32_cv             0.17 %          0.18 %             8      0.02%        0.02%        0.00%               0.02%            0.17%
ascon80pq_aead_decrypt/4096/32_mean        13046 ns        13045 ns            8   60.6878k      14.7015     151.873k             2.50253      301.794Mi/s
ascon80pq_aead_decrypt/4096/32_median      13011 ns        13010 ns            8   60.6777k      14.6991     151.873k             2.50295      302.589Mi/s
ascon80pq_aead_decrypt/4096/32_stddev       75.6 ns         75.3 ns            8    33.1297     8.02561m     2.95285m              1.366m      1.73463Mi/s
ascon80pq_aead_decrypt/4096/32_cv           0.58 %          0.58 %             8      0.05%        0.05%        0.00%               0.05%            0.57%
ascon_prf/512/32_mean                        761 ns          761 ns            8    3.4371k       6.3182      11.747k             3.41771      681.949Mi/s
ascon_prf/512/32_median                      768 ns          768 ns            8   3.43669k      6.31745      11.747k             3.41811      675.239Mi/s
ascon_prf/512/32_stddev                     21.4 ns         21.4 ns            8    2.61516     4.80728m     184.553u            2.59968m      19.3228Mi/s
ascon_prf/512/32_cv                         2.81 %          2.81 %             8      0.08%        0.08%        0.00%               0.08%            2.83%
ascon_prf/1024/64_mean                      1458 ns         1458 ns            8   6.54506k      6.01568      22.295k             3.40652      711.777Mi/s
ascon_prf/1024/64_median                    1466 ns         1466 ns            8    6.5178k      5.99063      22.295k             3.42063      707.942Mi/s
ascon_prf/1024/64_stddev                    30.5 ns         30.5 ns            8    43.8046    0.0402616            0           0.0227297      15.0914Mi/s
ascon_prf/1024/64_cv                        2.09 %          2.09 %             8      0.67%        0.67%        0.00%               0.67%            2.12%
ascon_prfs_authenticate/16_mean             40.9 ns         40.8 ns            8    184.034      5.75105          670             3.64064      747.754Mi/s
ascon_prfs_authenticate/16_median           41.0 ns         41.0 ns            8    184.055      5.75172          670             3.64022       744.76Mi/s
ascon_prfs_authenticate/16_stddev           1.26 ns         1.26 ns            8   0.122998     3.84369m            0            2.43466m      23.1312Mi/s
ascon_prfs_authenticate/16_cv               3.09 %          3.09 %             8      0.07%        0.07%        0.00%               0.07%            3.09%
ascon_mac_authenticate/64_mean               194 ns          194 ns            8    870.523      10.8815       2.904k             3.33598      394.181Mi/s
ascon_mac_authenticate/64_median             194 ns          194 ns            8    871.655      10.8957       2.904k             3.33159      393.589Mi/s
ascon_mac_authenticate/64_stddev            2.95 ns         2.95 ns            8    3.53966    0.0442457     65.2493u           0.0136473      6.08701Mi/s
ascon_mac_authenticate/64_cv                1.53 %          1.52 %             8      0.41%        0.41%        0.00%               0.41%            1.54%
ascon_xof/128/32_mean                        777 ns          777 ns            8   3.52066k      22.0041      12.225k             3.47237      196.491Mi/s
ascon_xof/128/32_median                      773 ns          773 ns            8   3.51961k      21.9976      12.225k              3.4734      197.516Mi/s
ascon_xof/128/32_stddev                     24.4 ns         24.4 ns            8    2.74602    0.0171626     184.553u            2.70548m      6.13398Mi/s
ascon_xof/128/32_cv                         3.14 %          3.14 %             8      0.08%        0.08%        0.00%               0.08%            3.12%
ascon_xofa/128/32_mean                       545 ns          545 ns            8   2.43839k      15.2399       8.737k             3.58313      280.528Mi/s
ascon_xofa/128/32_median                     547 ns          547 ns            8   2.43603k      15.2252       8.737k             3.58657      279.117Mi/s
ascon_xofa/128/32_stddev                    22.2 ns         22.2 ns            8    6.31779    0.0394862            0            9.24236m      11.2126Mi/s
ascon_xofa/128/32_cv                        4.08 %          4.07 %             8      0.26%        0.26%        0.00%               0.26%            4.00%
ascon_xof/128/64_mean                        941 ns          941 ns            8   4.25107k       22.141      14.457k              3.4008      194.677Mi/s
ascon_xof/128/64_median                      950 ns          950 ns            8   4.25287k      22.1504      14.457k             3.39935      192.842Mi/s
ascon_xof/128/64_stddev                     26.9 ns         27.0 ns            8    6.11097     0.031828     319.655u            4.89396m      5.61157Mi/s
ascon_xof/128/64_cv                         2.86 %          2.86 %             8      0.14%        0.14%        0.00%               0.14%            2.88%
ascon128_aead_encrypt/256/32_mean           1029 ns         1029 ns            8   4.79096k      16.6353      12.046k             2.51432      266.847Mi/s
ascon128_aead_encrypt/256/32_median         1029 ns         1028 ns            8   4.79101k      16.6355      12.046k             2.51429      267.056Mi/s
ascon128_aead_encrypt/256/32_stddev         2.39 ns         2.36 ns            8   0.415767     1.44363m     260.997u            218.196u      624.474Ki/s
ascon128_aead_encrypt/256/32_cv             0.23 %          0.23 %             8      0.01%        0.01%        0.00%               0.01%            0.23%
ascon_hash/128_mean                          785 ns          785 ns            8   3.51656k      21.9785      12.197k             3.46844      194.466Mi/s
ascon_hash/128_median                        789 ns          788 ns            8   3.51653k      21.9783      12.197k             3.46848       193.53Mi/s
ascon_hash/128_stddev                       19.7 ns         19.7 ns            8    1.29437     8.08984m     184.553u            1.27662m      4.94706Mi/s
ascon_hash/128_cv                           2.51 %          2.51 %             8      0.04%        0.04%        0.00%               0.04%            2.54%
ascon128_aead_decrypt/256/32_mean           1030 ns         1030 ns            8   4.79167k      16.6377      12.215k             2.54922      266.722Mi/s
ascon128_aead_decrypt/256/32_median         1029 ns         1029 ns            8   4.79127k      16.6363      12.215k             2.54943      266.977Mi/s
ascon128_aead_decrypt/256/32_stddev         5.87 ns         5.86 ns            8     1.2139     4.21493m            0            645.596u      1.51135Mi/s
ascon128_aead_decrypt/256/32_cv             0.57 %          0.57 %             8      0.03%        0.03%        0.00%               0.03%            0.57%
ascon_mac_verify/4096_mean                  5021 ns         5021 ns            8   22.6906k      5.49676       77.26k             3.40516      784.541Mi/s
ascon_mac_verify/4096_median                5053 ns         5052 ns            8   22.6445k      5.48559       77.26k             3.41187      779.185Mi/s
ascon_mac_verify/4096_stddev                 129 ns          129 ns            8    198.177     0.048008            0           0.0296697      20.2398Mi/s
ascon_mac_verify/4096_cv                    2.56 %          2.56 %             8      0.87%        0.87%        0.00%               0.87%            2.58%
ascon_prf/512/16_mean                        734 ns          734 ns            8     3.277k      6.20643      11.193k             3.41563      685.863Mi/s
ascon_prf/512/16_median                      740 ns          740 ns            8    3.2768k      6.20607      11.193k             3.41583      680.662Mi/s
ascon_prf/512/16_stddev                     14.7 ns         14.7 ns            8    3.15411      5.9737m            0            3.28573m      14.1385Mi/s
ascon_prf/512/16_cv                         2.00 %          2.00 %             8      0.10%        0.10%        0.00%               0.10%            2.06%
ascon_xof/256/64_mean                       1543 ns         1543 ns            8   6.93626k      21.6758      23.817k             3.43371      198.005Mi/s
ascon_xof/256/64_median                     1556 ns         1556 ns            8   6.93344k       21.667      23.817k             3.43509      196.173Mi/s
ascon_xof/256/64_stddev                     57.8 ns         57.8 ns            8     16.804    0.0525125     521.995u            8.28707m      7.36522Mi/s
ascon_xof/256/64_cv                         3.75 %          3.75 %             8      0.24%        0.24%        0.00%               0.24%            3.72%
ascon_hasha/64_mean                          338 ns          338 ns            8   1.51895k      15.8224       5.437k             3.57945      271.222Mi/s
ascon_hasha/64_median                        342 ns          342 ns            8   1.51883k      15.8211       5.437k             3.57973      268.018Mi/s
ascon_hasha/64_stddev                       11.1 ns         11.1 ns            8    1.47948    0.0154113     92.2765u            3.48517m      9.02413Mi/s
ascon_hasha/64_cv                           3.30 %          3.29 %             8      0.10%        0.10%        0.00%               0.10%            3.33%
ascon128a_aead_encrypt/512/32_mean          1118 ns         1118 ns            8   5.02661k      9.24009      17.024k             3.38678      464.255Mi/s
ascon128a_aead_encrypt/512/32_median        1127 ns         1127 ns            8   5.02658k      9.24004      17.024k              3.3868       460.51Mi/s
ascon128a_aead_encrypt/512/32_stddev        25.7 ns         25.7 ns            8    4.13583     7.60263m            0            2.78653m      10.8279Mi/s
ascon128a_aead_encrypt/512/32_cv            2.30 %          2.30 %             8      0.08%        0.08%        0.00%               0.08%            2.33%
ascon_xof/64/64_mean                         639 ns          639 ns            8   2.88432k      22.5338       9.777k             3.38972      191.237Mi/s
ascon_xof/64/64_median                       646 ns          646 ns            8    2.8852k      22.5406       9.777k             3.38868      189.091Mi/s
ascon_xof/64/64_stddev                      12.6 ns         12.6 ns            8    6.40547    0.0500427     130.499u             7.5299m      3.84697Mi/s
ascon_xof/64/64_cv                          1.98 %          1.98 %             8      0.22%        0.22%        0.00%               0.22%            2.01%
ascon_permutation<12>_mean                  34.8 ns         34.8 ns            8    160.264       4.0066          520             3.24465      1.07122Gi/s
ascon_permutation<12>_median                34.8 ns         34.7 ns            8    160.139      4.00348          520             3.24718      1.07207Gi/s
ascon_permutation<12>_stddev               0.323 ns        0.323 ns            8   0.283496     7.08739m            0            5.73184m      10.1648Mi/s
ascon_permutation<12>_cv                    0.93 %          0.93 %             8      0.18%        0.18%        0.00%               0.18%            0.93%
ascon_prfs_verify/16_mean                   43.6 ns         43.6 ns            8    192.988      6.03088          682              3.5339      700.026Mi/s
ascon_prfs_verify/16_median                 44.0 ns         44.0 ns            8    192.989      6.03089          682             3.53389      693.776Mi/s
ascon_prfs_verify/16_stddev                 1.01 ns         1.01 ns            8   0.358915    0.0112161            0            6.57053m      16.7013Mi/s
ascon_prfs_verify/16_cv                     2.31 %          2.31 %             8      0.19%        0.19%        0.00%               0.19%            2.39%
ascon_prfs_authenticate/4_mean              50.8 ns         50.8 ns            8    234.697      11.7348          668             2.84623      375.461Mi/s
ascon_prfs_authenticate/4_median            50.8 ns         50.8 ns            8    234.742      11.7371          668             2.84567      375.341Mi/s
ascon_prfs_authenticate/4_stddev           0.450 ns        0.451 ns            8   0.329858    0.0164929     8.15617u            4.00332m      3.32911Mi/s
ascon_prfs_authenticate/4_cv                0.89 %          0.89 %             8      0.14%        0.14%        0.00%               0.14%            0.89%
ascon_hash/64_mean                           492 ns          492 ns            8   2.17168k      22.6217       7.517k             3.46138      186.258Mi/s
ascon_hash/64_median                         492 ns          492 ns            8    2.1713k      22.6177       7.517k             3.46198      186.214Mi/s
ascon_hash/64_stddev                        5.15 ns         5.15 ns            8    2.45693     0.025593            0            3.90898m      1.94581Mi/s
ascon_hash/64_cv                            1.05 %          1.05 %             8      0.11%        0.11%        0.00%               0.11%            1.04%
ascon128a_aead_decrypt/128/32_mean           410 ns          410 ns            8   1.83758k      11.4849       6.139k             3.34081      372.147Mi/s
ascon128a_aead_decrypt/128/32_median         410 ns          410 ns            8   1.83755k      11.4847       6.139k             3.34086      371.841Mi/s
ascon128a_aead_decrypt/128/32_stddev        8.44 ns         8.44 ns            8   0.406743     2.54214m     92.2765u            739.437u      7.81308Mi/s
ascon128a_aead_decrypt/128/32_cv            2.06 %          2.06 %             8      0.02%        0.02%        0.00%               0.02%            2.10%
ascon128a_aead_decrypt/64/32_mean            299 ns          299 ns            8   1.32668k      13.8195       4.436k              3.3437      306.571Mi/s
ascon128a_aead_decrypt/64/32_median          301 ns          301 ns            8   1.32612k      13.8138       4.436k              3.3451      304.257Mi/s
ascon128a_aead_decrypt/64/32_stddev         4.98 ns         4.97 ns            8    1.47089    0.0153217            0            3.69888m      5.20923Mi/s
ascon128a_aead_decrypt/64/32_cv             1.67 %          1.66 %             8      0.11%        0.11%        0.00%               0.11%            1.70%
ascon_hash/512_mean                         2626 ns         2626 ns            8   11.5501k      21.2318      40.277k             3.48716      197.667Mi/s
ascon_hash/512_median                       2658 ns         2658 ns            8   11.5501k      21.2317      40.277k             3.48717      195.207Mi/s
ascon_hash/512_stddev                       66.0 ns         66.0 ns            8     3.7498     6.89302m            0            1.13221m      5.19665Mi/s
ascon_hash/512_cv                           2.51 %          2.51 %             8      0.03%        0.03%        0.00%               0.03%            2.63%
ascon_prf/64/32_mean                         233 ns          233 ns            8   1.03858k      10.8185       3.487k             3.35752      393.378Mi/s
ascon_prf/64/32_median                       233 ns          233 ns            8   1.03975k      10.8307       3.487k             3.35369      393.552Mi/s
ascon_prf/64/32_stddev                      2.65 ns         2.64 ns            8    3.81962    0.0397877            0           0.0124397      4.45801Mi/s
ascon_prf/64/32_cv                          1.14 %          1.13 %             8      0.37%        0.37%        0.00%               0.37%            1.13%
ascon_xof/2048/32_mean                      9786 ns         9785 ns            8    43.687k      21.0034     152.625k              3.4936      202.806Mi/s
ascon_xof/2048/32_median                    9793 ns         9791 ns            8   43.6855k      21.0027     152.625k             3.49372      202.589Mi/s
ascon_xof/2048/32_stddev                     207 ns          207 ns            8    14.9146     7.17048m            0            1.19248m      4.37951Mi/s
ascon_xof/2048/32_cv                        2.11 %          2.12 %             8      0.03%        0.03%        0.00%               0.03%            2.16%
ascon128_aead_decrypt/1024/32_mean          3409 ns         3409 ns            8   15.9264k      15.0819      40.139k             2.52027      295.422Mi/s
ascon128_aead_decrypt/1024/32_median        3409 ns         3409 ns            8   15.9266k       15.082      40.139k             2.52025      295.454Mi/s
ascon128_aead_decrypt/1024/32_stddev        5.08 ns         5.03 ns            8    2.26379     2.14374m     521.995u            358.281u      446.818Ki/s
ascon128_aead_decrypt/1024/32_cv            0.15 %          0.15 %             8      0.01%        0.01%        0.00%               0.01%            0.15%
ascon128a_aead_decrypt/1024/32_mean         2023 ns         2022 ns            8    9.1035k      8.62074      30.317k             3.33026      498.096Mi/s
ascon128a_aead_decrypt/1024/32_median       2026 ns         2026 ns            8   9.10462k       8.6218      30.317k             3.32985      497.056Mi/s
ascon128a_aead_decrypt/1024/32_stddev       36.4 ns         36.4 ns            8    5.60474     5.30752m            0            2.05025m        9.184Mi/s
ascon128a_aead_decrypt/1024/32_cv           1.80 %          1.80 %             8      0.06%        0.06%        0.00%               0.06%            1.84%
ascon_prf/128/64_mean                        384 ns          384 ns            8   1.70361k      8.87295       5.775k             3.38987      477.362Mi/s
ascon_prf/128/64_median                      383 ns          383 ns            8   1.70381k        8.874       5.775k             3.38947      477.922Mi/s
ascon_prf/128/64_stddev                     2.84 ns         2.84 ns            8    2.14609    0.0111775     65.2493u            4.27084m      3.54499Mi/s
ascon_prf/128/64_cv                         0.74 %          0.74 %             8      0.13%        0.13%        0.00%               0.13%            0.74%
ascon128a_aead_decrypt/2048/32_mean         3884 ns         3884 ns            8   17.3801k      8.35581      57.949k             3.33422      510.746Mi/s
ascon128a_aead_decrypt/2048/32_median       3875 ns         3875 ns            8    17.382k      8.35673      57.949k             3.33385      511.882Mi/s
ascon128a_aead_decrypt/2048/32_stddev       35.3 ns         35.2 ns            8    7.06645     3.39733m            0            1.35641m      4.62973Mi/s
ascon128a_aead_decrypt/2048/32_cv           0.91 %          0.91 %             8      0.04%        0.04%        0.00%               0.04%            0.91%
ascon128_aead_encrypt/1024/32_mean          3451 ns         3451 ns            8    16.064k      15.2121      39.694k             2.47099      291.874Mi/s
ascon128_aead_encrypt/1024/32_median        3446 ns         3446 ns            8   16.0596k      15.2079      39.694k             2.47167      292.271Mi/s
ascon128_aead_encrypt/1024/32_stddev        20.6 ns         20.6 ns            8     12.804     0.012125            0            1.96904m      1.73051Mi/s
ascon128_aead_encrypt/1024/32_cv            0.60 %          0.60 %             8      0.08%        0.08%        0.00%               0.08%            0.59%
ascon80pq_aead_encrypt/512/32_mean          1835 ns         1835 ns            8   8.53975k      15.6981        21.3k             2.49422      282.746Mi/s
ascon80pq_aead_encrypt/512/32_median        1830 ns         1830 ns            8   8.53979k      15.6981        21.3k             2.49421      283.515Mi/s
ascon80pq_aead_encrypt/512/32_stddev        10.6 ns         10.6 ns            8    2.03389     3.73877m            0            594.057u      1.62461Mi/s
ascon80pq_aead_encrypt/512/32_cv            0.58 %          0.58 %             8      0.02%        0.02%        0.00%               0.02%            0.57%
ascon_xofa/512/32_mean                      1776 ns         1776 ns            8   7.84282k      14.4169      28.369k              3.6172      292.485Mi/s
ascon_xofa/512/32_median                    1805 ns         1805 ns            8   7.84364k      14.4185      28.369k             3.61681      287.494Mi/s
ascon_xofa/512/32_stddev                    61.6 ns         61.6 ns            8    2.00963     3.69417m      639.31u            926.977u      10.4761Mi/s
ascon_xofa/512/32_cv                        3.47 %          3.47 %             8      0.03%        0.03%        0.00%               0.03%            3.58%
ascon_xofa/64/64_mean                        448 ns          448 ns            8   2.00597k      15.6716       7.025k             3.50211      272.541Mi/s
ascon_xofa/64/64_median                      455 ns          455 ns            8   2.00523k      15.6659       7.025k             3.50335      268.577Mi/s
ascon_xofa/64/64_stddev                     15.7 ns         15.7 ns            8    8.92547    0.0697302     92.2765u           0.0155816      9.63116Mi/s
ascon_xofa/64/64_cv                         3.49 %          3.49 %             8      0.44%        0.44%        0.00%               0.44%            3.53%
ascon_hasha/128_mean                         554 ns          554 ns            8   2.43323k      15.2077       8.709k              3.5792      275.604Mi/s
ascon_hasha/128_median                       554 ns          554 ns            8   2.43249k      15.2031       8.709k             3.58028      275.392Mi/s
ascon_hasha/128_stddev                      11.9 ns         11.9 ns            8    3.17577    0.0198485            0            4.66874m      6.07158Mi/s
ascon_hasha/128_cv                          2.14 %          2.14 %             8      0.13%        0.13%        0.00%               0.13%            2.20%
ascon_hasha/4096_mean                      13292 ns        13291 ns            8   58.3977k      14.1467     211.573k             3.62297      296.357Mi/s
ascon_hasha/4096_median                    13381 ns        13381 ns            8   58.3973k      14.1466     211.573k               3.623      294.219Mi/s
ascon_hasha/4096_stddev                      325 ns          325 ns            8     29.265     7.08939m     2.95285m            1.81541m       7.5732Mi/s
ascon_hasha/4096_cv                         2.44 %          2.44 %             8      0.05%        0.05%        0.00%               0.05%            2.56%
ascon_xof/512/64_mean                       2778 ns         2778 ns            8   12.2863k      21.3304      42.537k             3.46215      197.917Mi/s
ascon_xof/512/64_median                     2779 ns         2779 ns            8   12.2879k      21.3332      42.537k             3.46169      197.702Mi/s
ascon_xof/512/64_stddev                     81.6 ns         81.6 ns            8    16.7749    0.0291231            0            4.72895m       5.7793Mi/s
ascon_xof/512/64_cv                         2.94 %          2.94 %             8      0.14%        0.14%        0.00%               0.14%            2.92%
ascon128_aead_encrypt/4096/32_mean         13133 ns        13132 ns            8   61.2699k      14.8425     150.286k             2.45285      299.777Mi/s
ascon128_aead_encrypt/4096/32_median       13132 ns        13131 ns            8   61.2617k      14.8405     150.286k             2.45318      299.801Mi/s
ascon128_aead_encrypt/4096/32_stddev        39.6 ns         39.5 ns            8    52.8099    0.0127931            0            2.11286m       921.21Ki/s
ascon128_aead_encrypt/4096/32_cv            0.30 %          0.30 %             8      0.09%        0.09%        0.00%               0.09%            0.30%
ascon_prf/2048/64_mean                      2720 ns         2720 ns            8   12.0788k      5.71915      41.175k             3.40905      740.626Mi/s
ascon_prf/2048/64_median                    2728 ns         2728 ns            8   12.0174k      5.69006      41.175k             3.42628      738.339Mi/s
ascon_prf/2048/64_stddev                    30.6 ns         30.6 ns            8    97.4735    0.0461522            0           0.0273837      8.38369Mi/s
ascon_prf/2048/64_cv                        1.13 %          1.13 %             8      0.81%        0.81%        0.00%               0.80%            1.13%
ascon_xof/1024/64_mean                      5205 ns         5205 ns            8   23.0023k      21.1418      79.977k             3.47692       199.37Mi/s
ascon_xof/1024/64_median                    5195 ns         5195 ns            8   23.0023k      21.1418      79.977k             3.47692      199.743Mi/s
ascon_xof/1024/64_stddev                    52.3 ns         52.2 ns            8    14.0853    0.0129461     1.47642m            2.12841m      1.98819Mi/s
ascon_xof/1024/64_cv                        1.00 %          1.00 %             8      0.06%        0.06%        0.00%               0.06%            1.00%
ascon_xofa/4096/64_mean                    13356 ns        13355 ns            8   58.8613k      14.1493     213.161k             3.62141      297.365Mi/s
ascon_xofa/4096/64_median                  13550 ns        13549 ns            8   58.8638k      14.1499     213.161k             3.62126      292.815Mi/s
ascon_xofa/4096/64_stddev                    439 ns          439 ns            8     29.228     7.02596m     2.95285m            1.79841m      10.1127Mi/s
ascon_xofa/4096/64_cv                       3.29 %          3.28 %             8      0.05%        0.05%        0.00%               0.05%            3.40%
ascon_prf/256/32_mean                        456 ns          456 ns            8   2.09057k      7.25893       7.027k             3.36129      602.656Mi/s
ascon_prf/256/32_median                      449 ns          449 ns            8    2.0907k      7.25938       7.027k             3.36107      612.266Mi/s
ascon_prf/256/32_stddev                     12.2 ns         12.2 ns            8    3.56444    0.0123765     92.2765u            5.73236m      15.7738Mi/s
ascon_prf/256/32_cv                         2.67 %          2.67 %             8      0.17%        0.17%        0.00%               0.17%            2.62%
ascon80pq_aead_encrypt/1024/32_mean         3448 ns         3448 ns            8   16.0669k      15.2149      39.732k             2.47291      292.103Mi/s
ascon80pq_aead_encrypt/1024/32_median       3446 ns         3445 ns            8   16.0678k      15.2157      39.732k             2.47278      292.291Mi/s
ascon80pq_aead_encrypt/1024/32_stddev       9.12 ns         9.19 ns            8    12.2977    0.0116456     738.212u            1.89282m      795.275Ki/s
ascon80pq_aead_encrypt/1024/32_cv           0.26 %          0.27 %             8      0.08%        0.08%        0.00%               0.08%            0.27%
ascon_permutation<1>_mean                   10.1 ns         10.1 ns            8    47.1595      1.17899           58             1.22987      3.67306Gi/s
ascon_permutation<1>_median                 10.1 ns         10.1 ns            8      47.14       1.1785           58             1.23038      3.68159Gi/s
ascon_permutation<1>_stddev                0.065 ns        0.065 ns            8  0.0699261     1.74815m      720.91n            1.82199m      23.9124Mi/s
ascon_permutation<1>_cv                     0.64 %          0.64 %             8      0.15%        0.15%        0.00%               0.15%            0.64%
ascon128_aead_decrypt/128/32_mean            636 ns          636 ns            8    2.9235k      18.2719       7.561k             2.58628      240.082Mi/s
ascon128_aead_decrypt/128/32_median          628 ns          628 ns            8   2.92353k      18.2721       7.561k             2.58625      243.015Mi/s
ascon128_aead_decrypt/128/32_stddev         24.2 ns         24.2 ns            8   0.318693     1.99183m            0            281.981u      8.46626Mi/s
ascon128_aead_decrypt/128/32_cv             3.81 %          3.80 %             8      0.01%        0.01%        0.00%               0.01%            3.53%
ascon_prf/256/16_mean                        427 ns          427 ns            8   1.91752k      7.04971       6.473k             3.37571      608.251Mi/s
ascon_prf/256/16_median                      428 ns          428 ns            8   1.91762k      7.05009       6.473k             3.37553      605.486Mi/s
ascon_prf/256/16_stddev                     9.15 ns         9.14 ns            8    1.13256     4.16384m     92.2765u            1.99371m      13.1081Mi/s
ascon_prf/256/16_cv                         2.14 %          2.14 %             8      0.06%        0.06%        0.00%               0.06%            2.16%
ascon_prfs_authenticate/8_mean              41.0 ns         41.0 ns            8    183.688      7.65368          666             3.62573      559.454Mi/s
ascon_prfs_authenticate/8_median            41.4 ns         41.4 ns            8    183.684      7.65351          666             3.62579      552.969Mi/s
ascon_prfs_authenticate/8_stddev            1.38 ns         1.38 ns            8   0.456473    0.0190197            0            9.01998m      18.9852Mi/s
ascon_prfs_authenticate/8_cv                3.37 %          3.37 %             8      0.25%        0.25%        0.00%               0.25%            3.39%
ascon_xof/256/32_mean                       1392 ns         1392 ns            8   6.19459k       21.509      21.585k             3.48449      197.561Mi/s
ascon_xof/256/32_median                     1405 ns         1405 ns            8   6.19517k       21.511      21.585k             3.48417      195.563Mi/s
ascon_xof/256/32_stddev                     44.5 ns         44.5 ns            8    1.31044     4.55015m            0             737.21u      6.44382Mi/s
ascon_xof/256/32_cv                         3.20 %          3.20 %             8      0.02%        0.02%        0.00%               0.02%            3.26%
ascon128a_aead_decrypt/256/32_mean           651 ns          651 ns            8   2.88921k       10.032       9.593k             3.32029      421.918Mi/s
ascon128a_aead_decrypt/256/32_median         653 ns          653 ns            8   2.88914k      10.0317       9.593k             3.32037      420.661Mi/s
ascon128a_aead_decrypt/256/32_stddev        8.84 ns         8.82 ns            8    1.21451     4.21705m            0            1.39568m      5.72806Mi/s
ascon128a_aead_decrypt/256/32_cv            1.36 %          1.35 %             8      0.04%        0.04%        0.00%               0.04%            1.36%
ascon_permutation<8>_mean                   23.4 ns         23.4 ns            8    107.663      2.69157          352              3.2696      1.59245Gi/s
ascon_permutation<8>_median                 23.4 ns         23.4 ns            8    107.559      2.68898          352             3.27262       1.5929Gi/s
ascon_permutation<8>_stddev                0.288 ns        0.288 ns            8   0.719035    0.0179759     7.06345u           0.0216974      20.2206Mi/s
ascon_permutation<8>_cv                     1.23 %          1.23 %             8      0.67%        0.67%        0.00%               0.66%            1.24%
ascon_xofa/128/64_mean                       664 ns          664 ns            8   2.93895k       15.307      10.297k             3.50367      276.259Mi/s
ascon_xofa/128/64_median                     674 ns          674 ns            8   2.94121k      15.3188      10.297k             3.50094      271.775Mi/s
ascon_xofa/128/64_stddev                    24.5 ns         24.5 ns            8    9.62136    0.0501112     184.553u           0.0115033      10.5241Mi/s
ascon_xofa/128/64_cv                        3.69 %          3.69 %             8      0.33%        0.33%        0.00%               0.33%            3.81%
ascon_mac_verify/64_mean                     194 ns          194 ns            8    879.254       9.1589        2.92k             3.32119      473.258Mi/s
ascon_mac_verify/64_median                   195 ns          195 ns            8    878.216      9.14809        2.92k             3.32492      468.987Mi/s
ascon_mac_verify/64_stddev                  5.03 ns         5.03 ns            8    7.24631    0.0754824     184.553u           0.0271311      12.2867Mi/s
ascon_mac_verify/64_cv                      2.60 %          2.60 %             8      0.82%        0.82%        0.00%               0.82%            2.60%
ascon128_aead_decrypt/64/32_mean             430 ns          430 ns            8   1.99539k      20.7853       5.258k             2.63507      212.888Mi/s
ascon128_aead_decrypt/64/32_median           429 ns          429 ns            8   1.99531k      20.7844       5.258k             2.63519      213.508Mi/s
ascon128_aead_decrypt/64/32_stddev          3.97 ns         3.97 ns            8   0.173622     1.80856m     113.015u            229.251u        1.949Mi/s
ascon128_aead_decrypt/64/32_cv              0.92 %          0.92 %             8      0.01%        0.01%        0.00%               0.01%            0.92%
ascon_hash/1024_mean                        5002 ns         5002 ns            8   22.2606k      21.0801      77.717k             3.49124      201.493Mi/s
ascon_hash/1024_median                      5042 ns         5042 ns            8   22.2568k      21.0765      77.717k             3.49183      199.752Mi/s
ascon_hash/1024_stddev                       141 ns          141 ns            8    10.5063     9.94917m     1.80824m            1.64731m      5.75308Mi/s
ascon_hash/1024_cv                          2.82 %          2.82 %             8      0.05%        0.05%        0.00%               0.05%            2.86%
ascon_hash/2048_mean                        9786 ns         9786 ns            8   43.7059k      21.0124     152.597k             3.49145      202.864Mi/s
ascon_hash/2048_median                      9835 ns         9834 ns            8   43.7068k      21.0129     152.597k             3.49138      201.706Mi/s
ascon_hash/2048_stddev                       284 ns          284 ns            8    13.5133     6.49677m            0            1.07959m      5.99614Mi/s
ascon_hash/2048_cv                          2.90 %          2.90 %             8      0.03%        0.03%        0.00%               0.03%            2.96%
ascon128a_aead_encrypt/64/32_mean            286 ns          286 ns            8   1.29913k      13.5326       4.396k             3.38379      320.064Mi/s
ascon128a_aead_encrypt/64/32_median          285 ns          285 ns            8    1.2989k      13.5302       4.396k             3.38441      321.269Mi/s
ascon128a_aead_encrypt/64/32_stddev         9.13 ns         9.13 ns            8   0.476954     4.96827m     65.2493u            1.24191m      10.1731Mi/s
ascon128a_aead_encrypt/64/32_cv             3.19 %          3.19 %             8      0.04%        0.04%        0.00%               0.04%            3.18%
ascon_xofa/1024/64_mean                     3555 ns         3555 ns            8   15.5598k      14.3013      56.105k             3.60576      292.061Mi/s
ascon_xofa/1024/64_median                   3584 ns         3583 ns            8   15.5602k      14.3017      56.105k             3.60567      289.553Mi/s
ascon_xofa/1024/64_stddev                   92.1 ns         92.1 ns            8    9.86026     9.06274m     738.212u            2.28647m      7.95552Mi/s
ascon_xofa/1024/64_cv                       2.59 %          2.59 %             8      0.06%        0.06%        0.00%               0.06%            2.72%
ascon_hash/256_mean                         1390 ns         1390 ns            8    6.1951k      21.5108      21.557k             3.47969      197.791Mi/s
ascon_hash/256_median                       1405 ns         1404 ns            8   6.19476k      21.5096      21.557k             3.47988      195.568Mi/s
ascon_hash/256_stddev                       41.2 ns         41.2 ns            8    3.12104     0.010837     260.997u              1.753m      6.01339Mi/s
ascon_hash/256_cv                           2.96 %          2.96 %             8      0.05%        0.05%        0.00%               0.05%            3.04%
ascon_prf/2048/32_mean                      2641 ns         2641 ns            8   11.7476k      5.64789      40.067k              3.4109      751.119Mi/s
ascon_prf/2048/32_median                    2630 ns         2630 ns            8   11.6774k      5.61416      40.067k             3.43115       754.17Mi/s
ascon_prf/2048/32_stddev                    33.0 ns         33.0 ns            8    107.136    0.0515078     521.995u           0.0309716      9.31663Mi/s
ascon_prf/2048/32_cv                        1.25 %          1.25 %             8      0.91%        0.91%        0.00%               0.91%            1.24%
ascon80pq_aead_encrypt/64/32_mean            420 ns          420 ns            8   1.95463k      20.3607       5.172k             2.64603      218.148Mi/s
ascon80pq_aead_encrypt/64/32_median          419 ns          419 ns            8   1.95464k      20.3608       5.172k             2.64602      218.482Mi/s
ascon80pq_aead_encrypt/64/32_stddev         2.80 ns         2.79 ns            8    0.21224     2.21084m            0            287.324u      1.43529Mi/s
ascon80pq_aead_encrypt/64/32_cv             0.67 %          0.67 %             8      0.01%        0.01%        0.00%               0.01%            0.66%
ascon80pq_aead_decrypt/256/32_mean          1030 ns         1030 ns            8   4.78264k      16.6064      12.253k             2.56197      266.692Mi/s
ascon80pq_aead_decrypt/256/32_median        1025 ns         1025 ns            8   4.78271k      16.6066      12.253k             2.56194      267.952Mi/s
ascon80pq_aead_decrypt/256/32_stddev        10.6 ns         10.6 ns            8    1.01752     3.53304m     184.553u            545.105u       2.7117Mi/s
ascon80pq_aead_decrypt/256/32_cv            1.03 %          1.03 %             8      0.02%        0.02%        0.00%               0.02%            1.02%
ascon80pq_aead_decrypt/512/32_mean          1828 ns         1828 ns            8    8.5048k      15.6338      21.561k             2.53516      283.774Mi/s
ascon80pq_aead_decrypt/512/32_median        1825 ns         1825 ns            8   8.50399k      15.6323      21.561k              2.5354      284.234Mi/s
ascon80pq_aead_decrypt/512/32_stddev        10.5 ns         10.5 ns            8    2.72973     5.01789m            0            813.414u      1.60765Mi/s
ascon80pq_aead_decrypt/512/32_cv            0.58 %          0.57 %             8      0.03%        0.03%        0.00%               0.03%            0.57%
ascon_hasha/512_mean                        1778 ns         1778 ns            8   7.84255k      14.4164      28.341k             3.61375      292.165Mi/s
ascon_hasha/512_median                      1796 ns         1796 ns            8   7.84177k       14.415      28.341k             3.61411      288.886Mi/s
ascon_hasha/512_stddev                      60.9 ns         60.9 ns            8    3.43546     6.31518m     521.995u             1.5825m      10.3311Mi/s
ascon_hasha/512_cv                          3.42 %          3.42 %             8      0.04%        0.04%        0.00%               0.04%            3.54%
```

## Usage

`ascon` is a header-only C++{>=20} library, which is pretty easy to get started with.

- Include proper header file(s) ( living in `include` directory ) in your header/ source file.
- Use functions/ constants living under proper namespace of interest.
- When compiling, let your compiler know where it can find header files i.e. inside `include` and `subtle/include`, by using `-I` flag.

Scheme | Header to include | Namespace of interest | Example
:-: | :-- | :-- | :-:
Ascon-128 AEAD | `include/aead/ascon128.hpp` | `ascon128_aead::` | [example/ascon128_aead.cpp](./example/ascon128_aead.cpp)
Ascon-128a AEAD | `include/aead/ascon128a.hpp` | `ascon128a_aead::`  | [example/ascon128a_aead.cpp](./example/ascon128a_aead.cpp)
Ascon-80pq AEAD | `include/aead/ascon80pq.hpp` | `ascon80pq_aead::`  | [example/ascon80pq_aead.cpp](./example/ascon80pq_aead.cpp)
Ascon Hash | `include/hashing/ascon_hash.hpp` | `ascon_hash::` | [example/ascon_hash.cpp](./example/ascon_hash.cpp)
Ascon HashA | `include/hashing/ascon_hasha.hpp` | `ascon_hasha::` | [example/ascon_hasha.cpp](./example/ascon_hasha.cpp)
Ascon Xof | `include/hashing/ascon_xof.hpp` | `ascon_xof::` | [example/ascon_xof.cpp](./example/ascon_xof.cpp)
Ascon XofA | `include/hashing/ascon_xofa.hpp` | `ascon_xofa::` | [example/ascon_xofa.cpp](./example/ascon_xofa.cpp)
Ascon-PRF | `include/auth/ascon_prf.hpp` | `ascon_prf::` | [example/ascon_prf.cpp](./example/ascon_prf.cpp)
Ascon-MAC | `include/auth/ascon_mac.hpp` | `ascon_mac::` | [example/ascon_mac.cpp](./example/ascon_mac.cpp)
Ascon-MAC | `include/auth/ascon_prfs.hpp` | `ascon_prfs::` | [example/ascon_prfs.cpp](./example/ascon_prfs.cpp)

> **Note** Don't forget to also include path ( `-I ./subtle/include` ) to dependency library `subtle`, when compiling translation units, using this library.

Ascon permutation-based hashing schemes such as Ascon-{Hash, HashA, Xof, XofA} are all compile-time evaluable functions i.e. `constexpr`. Meaning if you've an input message, which is known at program compilation time, then it is possible to evaluate aforementioned functions on that message, during program compile-time itself. This can be useful if one needs to compute Ascon-{Hash, HashA, Xof, XofA} digests on static messages, which can be stored as part of program binary.

> **Note** Read more about `constexpr` functions @ https://en.cppreference.com/w/cpp/language/constexpr.

```cpp
// main.cpp
// Compile: g++ -std=c++20 -Wall -O3 -I include/ -I subtle/include/ main.cpp
// Execute: ./a.out

#include "hashing/ascon_hash.hpp"
#include <array>

// Returns a statically defined input message =
// 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
template<size_t mlen = 32>
constexpr std::array<uint8_t, mlen>
prepare_msg()
{
  std::array<uint8_t, mlen> msg{};
  std::iota(msg.begin(), msg.end(), 0);

  return msg;
}

// Given a statically known input message, computes Ascon-Hash digest of it.
constexpr std::array<uint8_t, ascon_hash::DIGEST_LEN>
eval_ascon_hash(std::span<const uint8_t, 32> msg)
{
  std::array<uint8_t, ascon_hash::DIGEST_LEN> md{};

  ascon_hash::ascon_hash_t hasher;
  hasher.absorb(msg);
  hasher.finalize();
  hasher.digest(md);

  return md;
}

int
main()
{
  // = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  constexpr auto msg = prepare_msg();
  constexpr auto computed_md = eval_ascon_hash(msg);

  // = 2a4f6f2b6b3ec2a6c47ba08d18c8ea561b493c13ccb35803fa8b9fb00a0f1f35
  constexpr auto expected_md = std::array<uint8_t, ascon_hash::DIGEST_LEN>{
    42, 79, 111, 43, 107, 62,  194, 166, 196, 123, 160, 141, 24, 200, 234, 86,
    27, 73, 60,  19, 204, 179, 88,  3,   250, 139, 159, 176, 10, 15,  31,  53
  };

  constexpr auto flg = expected_md == computed_md;
  static_assert(flg, "Must be able to evaluate Ascon-Hash during compile-time !");

  return 0;
}
```

I maintain some examples demonstrating usage of Ascon AEAD, Hash, Xof, PRF and MAC API.

```bash
# Assuming you've already cloned this ascon library and enabled git submodule.
$ ASCON_HEADERS=./include
$ SUBTLE_HEADERS=./subtle/include

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon128_aead.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon128a_aead.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon80pq_aead.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_hash.cpp && ./a.out
Ascon Hash

Message :	a2309f40cae3efc99941641caf1c2cddf6fcd52a031ff199dfe5f185bb5142e91539b0d6777ad7fe8c2300d42015b623517f31b5db0a94d7e3c8cb521f03aabb
Digest  :	b467a2107aa34754a8679dfbac795660a5a2be927f2b0216a8fad50202d17249

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_hasha.cpp && ./a.out
Ascon HashA

Message :	b11a401ec0ad387fdc890962e86158432ba31e50b8810e3360b4c6143a73f6f82364f6bd895938b7f0babdab065c17c7e0e7196c4a15eb345eb174f4f1da2de5
Digest  :	aa7463f3284c6b5d84aaf0c56a18ae79a2fbaf0e095111a0e65824e24892e419

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_xof.cpp && ./a.out
Ascon XOF

Message :	5265ce4d5d0b3a0d89c757e4b14049a4da449be528e9bb7606363717c16bf1f751ff64c4214aebe385ed4629b7eb14ff1a3f0ca6754ce6e54210efd33d117d41
Digest  :	65e2631e1478b8cec2fcbc8efbd954aefc4b20649d48818f06e95d355e4bda2b4d830ff05cd88f92a0d312c08e9c9959dcc8bb0e68c9ac0c0164becda6cd5acc

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_xofa.cpp && ./a.out
Ascon XOFA

Message :	6970b5465e902633d16179a2c6f68cb8ad52e853bda99cf72b9bb33bbb23d0df6b22b67e7e4dbe53e04abaa63d69ee84b0e8e87a3cdd94c9da105622ffa50755
Digest  :	52644d6ba60bd3eca3aa2dabfe69ae397ddcdd0f0abd5151bf1d0e23cb4da41b3ab75634e26bae4b19f78e95fbdd54961b35cb5c7ef3ec7639816f0833ffaea7

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_prf.cpp && ./a.out
Ascon-PRF

Key     :	518d6223f8895a8ad637e6c3fce66084
Message :	6a3fedca32ad7587663de617074eddbe64c084c658dbbb419dca2b4db5200af252a316cdcd042fdc31f11ba84a9925484d5f978e43172f3cf627a3b19e5f12f6
Tag     :	46e7936bf2468ead291854196bbaf4e00fc676a06fe33bd6326f31ac968e4aff73e8c3eb6cbc09884c226daceda36a26f0f601a93268ebcc384cc1d24baa6d5d

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_mac.cpp && ./a.out
Ascon-MAC

Key          :	53dffb5673f089f77f363fadcee2c69f
Message      :	13da8497fe16a3e4a61a937530f30ca072f470ec2a68449336264b272af354796037b8312479233f9d189bcc6e2a178b1dd5f91fc0094b59811541ac45b33b0a
Sender Tag   :	7fb21a028858927b54e148c6b25e68e2
Receiver Tag :	7fb21a028858927b54e148c6b25e68e2

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS example/ascon_prfs.cpp && ./a.out
Ascon-PRFShort

Key     :	f4c9dc526a8b03c3467abdc890575afc
Message :	f6ea9d6f4322de5c
Tag     :	3947e5220bf37c8ca807f2a1330134ad
```
