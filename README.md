> **Warning** This implementation attempts to provide you with constant-timeness though it is not yet audited. If you consider using it in production, be careful !

# ascon
Accelerated Ascon Cipher Suite: Light Weight Cryptography

## Overview

`ascon` cipher suite is selected by NIST as winner of **L**ight **W**eight **C**ryptography standardization effort and it's being standardized at the time of writing. Find more details @ https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices.

Following functionalities, from Ascon light weight cryptography suite, are implemented in this zero-dependency, header-only C++ library.

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

> **Note** Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> **Warning** Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and cipher text.

> **Note** Ascon based psuedo-random function and message authentication code scheme i.e. Ascon-PRF and Ascon-MAC respectively, support incremental message absorption/ authentication and squeezing.

> **Note** I've followed Ascon [specification](https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf) and another follow-up [paper](https://eprint.iacr.org/2021/1574.pdf), describing Ascon based authentication schemes, while working on this library implementation. I suggest you also go through these specifications to better understand Ascon cipher suite.

## Prerequisites

- Make sure you've a C++ compiler `g++`/ `clang++` installed, along with C++20 standard library.

```bash
$ g++ --version
g++ (Ubuntu 12.2.0-17ubuntu1) 12.2.0

$ clang++ --version
Ubuntu clang version 15.0.7
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- Build tools like `make`, `cmake` will be required for ease of building/ testing/ benchmarking.

```bash
$ make -v
GNU Make 4.3

$ cmake  --version
cmake version 3.25.1
```

- `subtle` is a ( git submodule -based ) dependency of this project - used for constant-time authentication tag comparison and setting memory locations of plain text to zero bytes, in case of authentication failure. Import `subtle` by issuing

```bash
# assuming you've already cloned `ascon`
git submodule update --init
```

- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed --- ensure it's globally installed; follow [this](https://github.com/google/benchmark/#installation) guide.
- **Note:** If you are on a machine running GNU/Linux kernel and you want to obtain following (see list below), for Ascon based constructions, you should consider building google-benchmark library with libPFM support, following [this](https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7) step-by-step guide. Find more about libPFM @ https://perfmon2.sourceforge.net.
    1) CPU cycle count.
    2) Retired instruction count.
    3) Cycles/ byte ( aka cpb ).
    4) Retired instructions/ cycle ( aka ipc ).

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification.

- Ensure functional correctness of Ascon AEAD, Hash and Xof routines for various combination of inputs.
- Assess whether this implementation of Ascon cipher suite is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found inside [kats](./kats/) directory. These KAT files are originally taken from Ascon reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

```bash
make -j $(nproc --all)
```

```bash
[==========] Running 21 tests from 4 test suites.
[----------] Global test environment set-up.
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

[----------] 6 tests from AsconAEAD
[ RUN      ] AsconAEAD.CorrectnessTestAscon128AEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128AEAD (69 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128AEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128AEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon128aAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon128aAEAD (67 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon128aAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon128aAEAD (0 ms)
[ RUN      ] AsconAEAD.CorrectnessTestAscon80pqAEAD
[       OK ] AsconAEAD.CorrectnessTestAscon80pqAEAD (69 ms)
[ RUN      ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD
[       OK ] AsconAEAD.KnownAnswerTestsAscon80pqAEAD (0 ms)
[----------] 6 tests from AsconAEAD (209 ms total)

[----------] 8 tests from AsconHashing
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHash
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHash (7 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHash
[       OK ] AsconHashing.KnownAnswerTestsAsconHash (3 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionAsconHashA
[       OK ] AsconHashing.IncrementalMessageAbsorptionAsconHashA (6 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconHashA
[       OK ] AsconHashing.KnownAnswerTestsAsconHashA (2 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof (2238 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXof
[       OK ] AsconHashing.KnownAnswerTestsAsconXof (3 ms)
[ RUN      ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA
[       OK ] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA (1734 ms)
[ RUN      ] AsconHashing.KnownAnswerTestsAsconXofA
[       OK ] AsconHashing.KnownAnswerTestsAsconXofA (2 ms)
[----------] 8 tests from AsconHashing (3999 ms total)

[----------] 3 tests from AsconAuth
[ RUN      ] AsconAuth.KnownAnswerTestsAsconMac
[       OK ] AsconAuth.KnownAnswerTestsAsconMac (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRF
[       OK ] AsconAuth.KnownAnswerTestsAsconPRF (1 ms)
[ RUN      ] AsconAuth.KnownAnswerTestsAsconPRFShort
[       OK ] AsconAuth.KnownAnswerTestsAsconPRFShort (0 ms)
[----------] 3 tests from AsconAuth (3 ms total)

[----------] Global test environment tear-down
[==========] 21 tests from 4 test suites ran. (4212 ms total)
[  PASSED  ] 21 tests.
```

## Benchmarking

For benchmarking routines of Ascon lightweight cipher suite, using `google-benchmark` library, while targeting CPU systems, with variable length input data, one may issue following commands.

```bash
make benchmark -j $(nproc --all) # If you haven't built google-benchmark library with libPFM support.
make perf -j $(nproc --all)      # Must do if your google-benchmark library is built with libPFM support.
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

> **Note** `make perf -j $(nproc --all)` - was issued when collecting following benchmarks. Notice, columns such as *cycles*, *cycles/ byte*, *instructions* and *instructions/ cycle*. Follow [this](https://github.com/google/benchmark/blob/main/docs/perf_counters.md) for more details.

### On 12th Gen Intel(R) Core(TM) i7-1260P ( Compiled with GCC )

```bash
2023-07-29T11:30:29+04:00
Running ./benchmarks/perf.out
Run on (16 X 1076.85 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.52, 0.47, 0.48
***WARNING*** There are 133 benchmarks with threads and 2 performance counters were requested. Beware counters will reflect the combined usage across all threads.
---------------------------------------------------------------------------------------------------------------------------------------------------
Benchmark                               Time             CPU   Iterations     CYCLES CYCLES/ BYTE INSTRUCTIONS INSTRUCTIONS/ CYCLE bytes_per_second
---------------------------------------------------------------------------------------------------------------------------------------------------
ascon_permutation<1>                 3.26 ns         3.26 ns    215334558    15.2372      0.38093           56             3.67522       11.4147G/s
ascon_permutation<6>                 18.1 ns         18.1 ns     38524544    84.6034      2.11508          264             3.12044       2.05379G/s
ascon_permutation<8>                 23.8 ns         23.8 ns     29453476    111.111      2.77777          376             3.38401       1.56651G/s
ascon_permutation<12>                35.9 ns         35.9 ns     19504130    167.287      4.18217          556             3.32363       1063.91M/s
ascon128_aead_encrypt/64/32           333 ns          333 ns      2104934   1.55217k      16.1685       4.729k              3.0467       275.299M/s
ascon128_aead_encrypt/128/32          486 ns          486 ns      1440231   2.27393k       14.212       6.809k             2.99438       313.682M/s
ascon128_aead_encrypt/256/32          792 ns          791 ns       884279   3.69944k      12.8453      10.969k             2.96505       347.013M/s
ascon128_aead_encrypt/512/32         1407 ns         1407 ns       499279   6.56916k      12.0757      19.289k              2.9363       368.696M/s
ascon128_aead_encrypt/1024/32        2622 ns         2622 ns       267111   12.2537k      11.6039      35.929k              2.9321       384.063M/s
ascon128_aead_encrypt/2048/32        5086 ns         5086 ns       137598   23.7583k      11.4223      69.209k             2.91304       390.044M/s
ascon128_aead_encrypt/4096/32       10003 ns        10002 ns        70141   46.7338k      11.3212     135.769k             2.90516       393.595M/s
ascon128_aead_decrypt/64/32           339 ns          339 ns      2065121   1.58414k      16.5014       4.882k             3.08181       269.865M/s
ascon128_aead_decrypt/128/32          491 ns          491 ns      1425740   2.29094k      14.3184       6.948k             3.03281       310.992M/s
ascon128_aead_decrypt/256/32          795 ns          795 ns       879929   3.71259k      12.8909       11.08k             2.98444       345.312M/s
ascon128_aead_decrypt/512/32         1402 ns         1402 ns       497547   6.54696k      12.0348      19.344k             2.95465       370.125M/s
ascon128_aead_decrypt/1024/32        2616 ns         2616 ns       267078   12.2277k      11.5793      35.872k             2.93367       384.973M/s
ascon128_aead_decrypt/2048/32        5057 ns         5057 ns       138356   23.6236k      11.3575      68.928k             2.91776       392.281M/s
ascon128_aead_decrypt/4096/32        9915 ns         9915 ns        70649   46.3461k      11.2272      135.04k             2.91373       397.062M/s
ascon128a_aead_encrypt/64/32          254 ns          254 ns      2766954   1.18435k       12.337       4.044k             3.41452       360.699M/s
ascon128a_aead_encrypt/128/32         353 ns          353 ns      1985500   1.64822k      10.3014        5.66k             3.43401       432.517M/s
ascon128a_aead_encrypt/256/32         551 ns          551 ns      1270972   2.57572k      8.94347       8.892k             3.45224       498.606M/s
ascon128a_aead_encrypt/512/32         947 ns          947 ns       740398   4.42699k      8.13784      15.356k             3.46873       548.085M/s
ascon128a_aead_encrypt/1024/32       1739 ns         1739 ns       401029   8.13075k      7.69957      28.284k             3.47865       579.122M/s
ascon128a_aead_encrypt/2048/32       3331 ns         3330 ns       211025   15.5538k       7.4778       54.14k             3.48082       595.618M/s
ascon128a_aead_encrypt/4096/32       6482 ns         6482 ns       107380    30.278k      7.33478     105.852k             3.49601       607.323M/s
ascon128a_aead_decrypt/64/32          261 ns          261 ns      2681953   1.21937k      12.7017        4.22k             3.46081       350.672M/s
ascon128a_aead_decrypt/128/32         359 ns          358 ns      1957658   1.67243k      10.4527       5.838k             3.49074       425.653M/s
ascon128a_aead_decrypt/256/32         556 ns          556 ns      1252849   2.59454k       9.0088       9.074k             3.49735        494.32M/s
ascon128a_aead_decrypt/512/32         949 ns          949 ns       744394   4.41172k      8.10979      15.546k             3.52379       546.708M/s
ascon128a_aead_decrypt/1024/32       1724 ns         1724 ns       405129   8.05328k      7.62621       28.49k             3.53769       584.267M/s
ascon128a_aead_decrypt/2048/32       3299 ns         3298 ns       212613   15.4064k      7.40692      54.378k             3.52957       601.382M/s
ascon128a_aead_decrypt/4096/32       6428 ns         6428 ns       108181   30.0018k      7.26787     106.154k             3.53826        612.47M/s
ascon80pq_aead_encrypt/64/32          333 ns          333 ns      2102148   1.55522k      16.2002       4.753k             3.05616        275.26M/s
ascon80pq_aead_encrypt/128/32         485 ns          485 ns      1441985   2.26718k      14.1698       6.825k             3.01035       314.857M/s
ascon80pq_aead_encrypt/256/32         789 ns          789 ns       882884   3.68305k      12.7884      10.969k             2.97823       348.107M/s
ascon80pq_aead_encrypt/512/32        1402 ns         1402 ns       500215   6.54033k      12.0227      19.257k             2.94435       370.165M/s
ascon80pq_aead_encrypt/1024/32       2608 ns         2608 ns       267591   12.1937k      11.5471      35.833k             2.93864       386.165M/s
ascon80pq_aead_encrypt/2048/32       5054 ns         5053 ns       138508    23.619k      11.3553      68.985k             2.92074       392.533M/s
ascon80pq_aead_encrypt/4096/32       9872 ns         9871 ns        70932   46.1607k      11.1823     135.289k             2.93083       398.808M/s
ascon80pq_aead_decrypt/64/32          341 ns          341 ns      2053272   1.59323k      16.5961       4.897k             3.07363       268.646M/s
ascon80pq_aead_decrypt/128/32         492 ns          492 ns      1422694   2.29693k      14.3558       6.939k             3.02098       310.447M/s
ascon80pq_aead_decrypt/256/32         794 ns          794 ns       879018   3.71243k      12.8904      11.023k             2.96922       345.752M/s
ascon80pq_aead_decrypt/512/32        1396 ns         1396 ns       501624   6.53322k      12.0096      19.191k             2.93745       371.581M/s
ascon80pq_aead_decrypt/1024/32       2607 ns         2607 ns       268391   12.1817k      11.5357      35.527k             2.91642       386.364M/s
ascon80pq_aead_decrypt/2048/32       5040 ns         5040 ns       137793   23.5373k       11.316      68.199k             2.89749       393.601M/s
ascon80pq_aead_decrypt/4096/32       9892 ns         9892 ns        70789   46.1699k      11.1846     133.543k             2.89243       397.994M/s
ascon_hash/64                         465 ns          465 ns      1504131   2.17093k      22.6138       7.072k             3.25759         196.8M/s
ascon_hash/128                        750 ns          750 ns       934330   3.50026k      21.8767       11.32k             3.23404       203.584M/s
ascon_hash/256                       1322 ns         1322 ns       530752    6.1639k      21.4024      19.816k             3.21485       207.775M/s
ascon_hash/512                       2455 ns         2455 ns       284917   11.4811k       21.105      36.808k             3.20595       211.308M/s
ascon_hash/1024                      4742 ns         4742 ns       147829   22.1334k      20.9597      70.792k             3.19842       212.386M/s
ascon_hash/2048                      9300 ns         9299 ns        75285   43.4214k      20.8757      138.76k             3.19566       213.316M/s
ascon_hash/4096                     18409 ns        18408 ns        38092   85.9558k      20.8226     274.696k             3.19578       213.858M/s
ascon_hasha/64                        324 ns          324 ns      2162899   1.51181k      15.7481       5.018k             3.31919       282.848M/s
ascon_hasha/128                       515 ns          514 ns      1360913   2.40099k      15.0062        7.89k             3.28614       296.588M/s
ascon_hasha/256                       897 ns          897 ns       781597   4.19077k      14.5513      13.634k             3.25334        306.08M/s
ascon_hasha/512                      1659 ns         1659 ns       422958   7.74939k      14.2452      25.122k              3.2418       312.776M/s
ascon_hasha/1024                     3184 ns         3184 ns       219606   14.8615k      14.0734      48.098k             3.23641       316.316M/s
ascon_hasha/2048                     6222 ns         6221 ns       112524   29.0949k       13.988       94.05k             3.23252       318.839M/s
ascon_hasha/4096                    12320 ns        12320 ns        56802   57.5871k      13.9504     185.954k             3.22909       319.556M/s
ascon_xof/64/32                       463 ns          463 ns      1512306   2.16366k      22.5382       7.143k             3.30134       197.741M/s
ascon_xof/128/32                      748 ns          747 ns       938475   3.49211k      21.8257      11.391k             3.26193       204.135M/s
ascon_xof/256/32                     1317 ns         1317 ns       530355   6.16034k      21.3901      19.887k             3.22823       208.526M/s
ascon_xof/512/32                     2456 ns         2456 ns       285453   11.4776k      21.0985      36.879k             3.21313        211.25M/s
ascon_xof/1024/32                    4747 ns         4746 ns       147727   22.1145k      20.9417      70.863k             3.20437       212.175M/s
ascon_xof/2048/32                    9298 ns         9298 ns        75200   43.4156k      20.8729     138.831k             3.19772       213.347M/s
ascon_xof/4096/32                   18423 ns        18421 ns        38089   85.9606k      20.8238     274.767k             3.19643       213.709M/s
ascon_xof/64/64                       613 ns          612 ns      1141121   2.85723k      22.3221       9.419k             3.29655         199.3M/s
ascon_xof/128/64                      895 ns          895 ns       778973   4.18854k      21.8153      13.667k             3.26295        204.58M/s
ascon_xof/256/64                     1464 ns         1464 ns       478319   6.83165k      21.3489      22.163k             3.24416       208.521M/s
ascon_xof/512/64                     2598 ns         2597 ns       269683   12.1496k      21.0931      39.155k             3.22273       211.484M/s
ascon_xof/1024/64                    4875 ns         4874 ns       143792   22.7934k      20.9499      73.139k             3.20877       212.872M/s
ascon_xof/2048/64                    9439 ns         9439 ns        74311   44.1026k      20.8819     141.107k             3.19951       213.393M/s
ascon_xof/4096/64                   18992 ns        18892 ns        34504   87.9831k      21.1498     277.043k             3.14882       209.998M/s
ascon_xofa/64/32                      322 ns          322 ns      2171080   1.50403k       15.667       5.078k             3.37625       284.369M/s
ascon_xofa/128/32                     512 ns          512 ns      1356504   2.39105k      14.9441       7.958k             3.32824       297.791M/s
ascon_xofa/256/32                     896 ns          896 ns       777661   4.17609k      14.5003      13.718k             3.28489       306.632M/s
ascon_xofa/512/32                    1643 ns         1643 ns       422755   7.66616k      14.0922      25.238k             3.29213       315.794M/s
ascon_xofa/1024/32                   3142 ns         3142 ns       222905   14.6699k      13.8919      48.278k             3.29096       320.505M/s
ascon_xofa/2048/32                   6139 ns         6138 ns       114080   28.6162k      13.7578      94.358k             3.29736       323.162M/s
ascon_xofa/4096/32                  12099 ns        12098 ns        57894   56.4896k      13.6845     186.518k             3.30181       325.406M/s
ascon_xofa/64/64                      426 ns          426 ns      1647597   1.98718k      15.5248       6.666k             3.35451       286.447M/s
ascon_xofa/128/64                     614 ns          614 ns      1137644   2.87061k      14.9511       9.546k             3.32543       298.246M/s
ascon_xofa/256/64                     988 ns          988 ns       705296   4.61728k       14.429      15.306k             3.31494       308.817M/s
ascon_xofa/512/64                    1738 ns         1738 ns       402237   8.12313k      14.1027      26.826k             3.30242        316.14M/s
ascon_xofa/1024/64                   3237 ns         3237 ns       215595   15.1042k      13.8826      49.866k             3.30146       320.552M/s
ascon_xofa/2048/64                   6218 ns         6218 ns       112740   29.0818k      13.7698      95.946k             3.29918       323.928M/s
ascon_xofa/4096/64                  12189 ns        12188 ns        57476   56.9044k       13.679     188.106k             3.30565       325.495M/s
ascon_prf/64/16                       183 ns          183 ns      3807012    857.931      10.7241       2.881k             3.35808       415.889M/s
ascon_prf/128/16                      256 ns          256 ns      2727698    1.1985k       8.3229       3.993k             3.33167       536.216M/s
ascon_prf/256/16                      402 ns          402 ns      1742326   1.87865k       6.9068       6.217k             3.30929       645.604M/s
ascon_prf/512/16                      693 ns          693 ns      1011064   3.23968k      6.13576      10.665k             3.29199       726.503M/s
ascon_prf/1024/16                    1275 ns         1275 ns       547764   5.96184k      5.73254      19.561k             3.28104       778.183M/s
ascon_prf/2048/16                    2495 ns         2482 ns       286559   11.5536k      5.59765      37.353k             3.23303       793.211M/s
ascon_prf/4096/16                    4942 ns         4907 ns       134893    22.774k      5.53843      72.937k             3.20264       799.182M/s
ascon_prf/64/32                       221 ns          221 ns      3184135    1029.04      10.7192       3.449k             3.35167       415.155M/s
ascon_prf/128/32                      294 ns          294 ns      2383099   1.36861k      8.55382       4.561k             3.33258       519.759M/s
ascon_prf/256/32                      440 ns          439 ns      1593846   2.04958k      7.11661       6.785k             3.31043       624.961M/s
ascon_prf/512/32                      731 ns          731 ns       956360   3.41066k       6.2696      11.233k              3.2935       709.905M/s
ascon_prf/1024/32                    1322 ns         1322 ns       534122   5.94095k       5.6259     19.5051k             3.28317       761.824M/s
ascon_prf/2048/32                    2477 ns         2476 ns       282348   11.5734k      5.56412      37.921k             3.27658       801.033M/s
ascon_prf/4096/32                    4812 ns         4812 ns       145460   22.4656k      5.44225      73.505k             3.27189        818.18M/s
ascon_prf/64/64                       292 ns          292 ns      2402900    1.3639k      10.6555       4.585k             3.36168       418.155M/s
ascon_prf/128/64                      370 ns          370 ns      1917389   1.70581k      8.88443       5.697k             3.33976       494.856M/s
ascon_prf/256/64                      510 ns          510 ns      1374763   2.38619k      7.45684       7.921k             3.31952       598.433M/s
ascon_prf/512/64                      801 ns          801 ns       870409   3.74792k       6.5068      12.369k             3.30023       685.645M/s
ascon_prf/1024/64                    1381 ns         1381 ns       507410   6.46597k      5.94298      21.265k             3.28876       751.151M/s
ascon_prf/2048/64                    2546 ns         2546 ns       274296   11.9101k      5.63923      39.057k             3.27933        791.15M/s
ascon_prf/4096/64                    4868 ns         4868 ns       143852   22.7992k      5.48058      74.641k             3.27384       815.039M/s
ascon_mac_authenticate/64             183 ns          183 ns      3833633     855.23      10.6904       2.841k             3.32191       417.309M/s
ascon_mac_authenticate/128            256 ns          256 ns      2731504   1.19488k      8.29781       3.953k             3.30827       537.292M/s
ascon_mac_authenticate/256            402 ns          401 ns      1742474    1.8742k      6.89046       6.177k              3.2958        646.31M/s
ascon_mac_authenticate/512            692 ns          692 ns      1013233   3.23212k      6.12143      10.625k             3.28732       727.684M/s
ascon_mac_authenticate/1024          1274 ns         1274 ns       547486   5.95744k       5.7283      19.521k             3.27675       778.797M/s
ascon_mac_authenticate/2048          2439 ns         2439 ns       287221   11.3926k      5.51966      37.313k              3.2752       807.061M/s
ascon_mac_authenticate/4096          4766 ns         4766 ns       146802   22.2556k      5.41234      72.897k             3.27545       822.852M/s
ascon_mac_verify/64                   190 ns          190 ns      3700332    885.178       9.2206       2.991k             3.37898       483.009M/s
ascon_mac_verify/128                  263 ns          263 ns      2664089   1.22505k      7.65655       4.103k             3.34926       580.483M/s
ascon_mac_verify/256                  409 ns          409 ns      1715095   1.90483k      6.61398       6.327k             3.32156       672.148M/s
ascon_mac_verify/512                  699 ns          699 ns      1001513   3.26531k      6.00242      10.775k             3.29984       742.626M/s
ascon_mac_verify/1024                1283 ns         1283 ns       546271   5.99222k      5.67445      19.671k             3.28276       784.961M/s
ascon_mac_verify/2048                2451 ns         2451 ns       286312   11.4342k      5.49719      37.463k             3.27641       809.263M/s
ascon_mac_verify/4096                4777 ns         4777 ns       145595   22.3201k        5.407      73.047k              3.2727       824.167M/s
ascon_prfs_authenticate/1            46.6 ns         46.6 ns     15012260    217.916      12.8186          600             2.75336       347.804M/s
ascon_prfs_authenticate/2            47.2 ns         47.2 ns     14853683    220.026      12.2237          602             2.73604       363.873M/s
ascon_prfs_authenticate/4            46.8 ns         46.8 ns     14924251    219.047      10.9523          599             2.73457       407.349M/s
ascon_prfs_authenticate/8            36.9 ns         36.9 ns     18954182    172.292      7.17884          597             3.46505       620.277M/s
ascon_prfs_authenticate/16           37.4 ns         37.4 ns     18146435    174.908      5.46588          598             3.41894       815.958M/s
ascon_prfs_verify/1                  51.1 ns         51.1 ns     13804411    238.842      14.0495          753             3.15271       317.077M/s
ascon_prfs_verify/2                  50.8 ns         50.8 ns     13797424    237.689       13.205          755             3.17642       337.635M/s
ascon_prfs_verify/4                  51.4 ns         51.4 ns     13892098      235.9       11.795          752              3.1878       371.236M/s
ascon_prfs_verify/8                  45.3 ns         45.3 ns     15494172    211.669      8.81955          750             3.54326       504.938M/s
ascon_prfs_verify/16                 45.0 ns         45.0 ns     15578077    209.766       6.5552          751             3.58017       678.661M/s
```

## Usage

`ascon` is a zero-dependency, header-only C++ library, which is pretty easy to get started with.

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
