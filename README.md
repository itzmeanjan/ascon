> [!CAUTION]
> This Ascon cipher suite implementation is conformant with Ascon specification @ https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf and I also try to make it timing leakage free, using `dudect` (see https://github.com/oreparaz/dudect) -based tests, but be informed that this implementation is not yet audited. *If you consider using it in production, be careful !*

# ascon
Ascon Cipher Suite: Light Weight Cryptography

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

> [!NOTE]
> Ascon Permutation-based hashing schemes are all `constexpr` functions - meaning one can evaluate Ascon-{Hash, HashA, Xof, XofA} on statically defined input message, during program compilation time itself. Read more about C++ `constexpr` functions @ https://en.cppreference.com/w/cpp/language/constexpr. See [usage](#usage) section below.

> [!WARNING]
> Associated data is never encrypted. AEAD scheme provides secrecy only for plain text but authenticity and integrity for both associated data and cipher text.

I've followed Ascon specification @ https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf ( specifying AEAD and Hashing schemes ) and another follow-up paper @ https://eprint.iacr.org/2021/1574.pdf, describing Ascon permutation -based authentication schemes, while working on this library implementation. I suggest you also go through these specifications to better understand Ascon cipher suite.

## Prerequisites

- C++ compiler, with C++20 standard library, `g++`/ `clang++`.

```bash
$ clang++ -v
Ubuntu clang version 17.0.2 (1~exp1ubuntu2.1)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
Found candidate GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/13
Selected GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/13
Candidate multilib: .;@m64
Selected multilib: .;@m64

$ g++ --version
Using built-in specs.
COLLECT_GCC=g++
COLLECT_LTO_WRAPPER=/usr/libexec/gcc/x86_64-linux-gnu/13/lto-wrapper
OFFLOAD_TARGET_NAMES=nvptx-none:amdgcn-amdhsa
OFFLOAD_TARGET_DEFAULT=1
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Ubuntu 13.2.0-4ubuntu3' --with-bugurl=file:///usr/share/doc/gcc-13/README.Bugs --enable-languages=c,ada,c++,go,d,fortran,objc,obj-c++,m2 --prefix=/usr --with-gcc-major-version-only --program-suffix=-13 --program-prefix=x86_64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/libexec --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --enable-bootstrap --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-plugin --enable-default-pie --with-system-zlib --enable-libphobos-checking=release --with-target-system-zlib=auto --enable-objc-gc=auto --enable-multiarch --disable-werror --enable-cet --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-offload-targets=nvptx-none=/build/gcc-13-XYspKM/gcc-13-13.2.0/debian/tmp-nvptx/usr,amdgcn-amdhsa=/build/gcc-13-XYspKM/gcc-13-13.2.0/debian/tmp-gcn/usr --enable-offload-defaulted --without-cuda-driver --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu --with-build-config=bootstrap-lto-lean --enable-link-serialization=2
Thread model: posix
Supported LTO compression algorithms: zlib zstd
gcc version 13.2.0 (Ubuntu 13.2.0-4ubuntu3)
```

- Build tools such as `make`, `cmake`.

```bash
$ make -v
GNU Make 4.3
Built for x86_64-pc-linux-gnu

$ cmake --version
cmake version 3.27.4
```

- For testing this library implementation, you need to globally install `google-test` library and headers. Follow this guide @ https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project if you don't have it installed.
- For benchmarking this library implementation, you need to have `google-benchmark` header and library installed - ensure it's globally installed; follow this guide @ https://github.com/google/benchmark/#installation.

> [!NOTE]
> If you are on a machine running GNU/Linux kernel and you want to measure *CPU cycles* and *cycles/ byte*, for Ascon -based constructions, you should consider building `google-benchmark` library with *libPFM* support, following this step-by-step guide @ https://gist.github.com/itzmeanjan/05dc3e946f635d00c5e0b21aae6203a7. Find more about libPFM @ https://perfmon2.sourceforge.net.

> [!TIP]
> Git submodule based dependencies will mostly be imported *automatically* ( i.e. when you execute build commands ), but in case that doesn't work, you can manually initialize and update them by issuing `$ git submodule update --init` from the root of this repository.

## Testing

For ensuring that Ascon cipher suite is implemented correctly and it's conformant with the specification.

- Ensure functional correctness of Ascon AEAD, hashing and authentication schemes for various combination of inputs.
- Assess whether this implementation of Ascon cipher suite is conformant with specification, using **K**nown **A**nswer **T**ests, which can be found inside [kats](./kats/) directory. These KAT files are originally taken from Ascon reference implementation repository i.e. https://github.com/ascon/ascon-c.git.

```bash
make -j
```

```bash
[25/25] AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof (472 ms)
PASSED TESTS (25/25):
       1 ms: build/tests/test.out AsconHashing.CompileTimeEvalAsconHash
       1 ms: build/tests/test.out AsconHashing.CompileTimeEvalAsconHashA
       1 ms: build/tests/test.out AsconAuth.KnownAnswerTestsAsconPRFShort
       1 ms: build/tests/test.out AsconPermutation.AsconPermWithAsconHashAIV
       1 ms: build/tests/test.out AsconPermutation.AsconPermWithAsconHashIV
       1 ms: build/tests/test.out AsconPermutation.AsconPermWithAsconXofIV
       2 ms: build/tests/test.out AsconHashing.CompileTimeEvalAsconXof
       2 ms: build/tests/test.out AsconAEAD.KnownAnswerTestsAscon128AEAD
       2 ms: build/tests/test.out AsconHashing.CompileTimeEvalAsconXofA
       3 ms: build/tests/test.out AsconAEAD.KnownAnswerTestsAscon80pqAEAD
       3 ms: build/tests/test.out AsconAEAD.KnownAnswerTestsAscon128aAEAD
       3 ms: build/tests/test.out AsconPermutation.AsconPermWithAsconXofAIV
       5 ms: build/tests/test.out AsconAuth.KnownAnswerTestsAsconPRF
       5 ms: build/tests/test.out AsconHashing.IncrementalMessageAbsorptionAsconHashA
       5 ms: build/tests/test.out AsconAuth.KnownAnswerTestsAsconMac
       6 ms: build/tests/test.out AsconHashing.IncrementalMessageAbsorptionAsconHash
       7 ms: build/tests/test.out AsconHashing.KnownAnswerTestsAsconHashA
       7 ms: build/tests/test.out AsconHashing.KnownAnswerTestsAsconXofA
       8 ms: build/tests/test.out AsconHashing.KnownAnswerTestsAsconHash
       8 ms: build/tests/test.out AsconHashing.KnownAnswerTestsAsconXof
     302 ms: build/tests/test.out AsconAEAD.CorrectnessTestAscon80pqAEAD
     302 ms: build/tests/test.out AsconAEAD.CorrectnessTestAscon128aAEAD
     306 ms: build/tests/test.out AsconAEAD.CorrectnessTestAscon128AEAD
     443 ms: build/tests/test.out AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXofA
     472 ms: build/tests/test.out AsconHashing.IncrementalMessageAbsorptionSqueezingAsconXof
```

In case you're interested in running timing leakage tests using `dudect`, execute following

```bash
# Can only be built and run x86_64 machine.
make dudect_test_build -j

# Before running the constant-time tests, it's a good idea to put all CPU cores on "performance" mode.
# You may find guide @ https://github.com/google/benchmark/blob/main/docs/reducing_variance.md helpful.

timeout 10m taskset -c 0 ./build/dudect/test_ascon128a_aead_encrypt.out
timeout 10m taskset -c 0 ./build/dudect/test_ascon128a_aead_decrypt.out
```

> [!NOTE]
> For now I've written timing leakage detection tests only for Ascon128a AEAD `encrypt` and `decrypt` functions. Ascon128 and Ascon80pq AEAD are not yet covered. Though remember, same Ascon mode of operation is used for all three AEAD instantiations. Hashing and authentication schemes are not yet tested for timing leakage.

> [!TIP]
> `dudect` documentation says if `t` statistic is `< 10`, we're *probably* good, yes *probably*. You may want to read `dudect` documentation @ https://github.com/oreparaz/dudect. Also you might find the original paper @ https://ia.cr/2016/1123 interesting.

```bash
# Ascon128a AEAD decrypt
...
meas:  112.96 M, max t:   +2.66, max tau: 2.50e-04, (5/tau)^2: 4.00e+08. For the moment, maybe constant time.
meas:  109.18 M, max t:   +2.69, max tau: 2.58e-04, (5/tau)^2: 3.77e+08. For the moment, maybe constant time.
meas:  109.27 M, max t:   +2.70, max tau: 2.59e-04, (5/tau)^2: 3.74e+08. For the moment, maybe constant time.
meas:  117.28 M, max t:   +2.62, max tau: 2.42e-04, (5/tau)^2: 4.26e+08. For the moment, maybe constant time.
meas:  109.45 M, max t:   +2.64, max tau: 2.52e-04, (5/tau)^2: 3.94e+08. For the moment, maybe constant time.
meas:  109.54 M, max t:   +2.64, max tau: 2.52e-04, (5/tau)^2: 3.93e+08. For the moment, maybe constant time.
meas:  109.63 M, max t:   +2.62, max tau: 2.50e-04, (5/tau)^2: 4.00e+08. For the moment, maybe constant time.
meas:  113.61 M, max t:   +2.64, max tau: 2.47e-04, (5/tau)^2: 4.08e+08. For the moment, maybe constant time.
meas:  113.70 M, max t:   +2.69, max tau: 2.53e-04, (5/tau)^2: 3.92e+08. For the moment, maybe constant time.
meas:  113.79 M, max t:   +2.72, max tau: 2.55e-04, (5/tau)^2: 3.86e+08. For the moment, maybe constant time.
meas:  113.89 M, max t:   +2.73, max tau: 2.55e-04, (5/tau)^2: 3.83e+08. For the moment, maybe constant time.
meas:  113.98 M, max t:   +2.71, max tau: 2.54e-04, (5/tau)^2: 3.88e+08. For the moment, maybe constant time.
meas:  114.07 M, max t:   +2.70, max tau: 2.53e-04, (5/tau)^2: 3.90e+08. For the moment, maybe constant time.
meas:  114.16 M, max t:   +2.73, max tau: 2.55e-04, (5/tau)^2: 3.84e+08. For the moment, maybe constant time.
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

> [!CAUTION]
> Ensure that you've disabled CPU frequency scaling, when benchmarking, following this guide @ https://github.com/google/benchmark/blob/main/docs/reducing_variance.md.

### On 12th Gen Intel(R) Core(TM) i7-1260P

Compiled with **gcc version 13.2.0 (Ubuntu 13.2.0-4ubuntu3).**

```bash
$ uname -srm
Linux 6.5.0-15-generic x86_64
```

```bash
2024-02-04T15:03:47+04:00
Running ./build/perfs/perf.out
Run on (16 X 709.949 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x8)
  L1 Instruction 32 KiB (x8)
  L2 Unified 1280 KiB (x8)
  L3 Unified 18432 KiB (x1)
Load Average: 0.29, 0.23, 0.29
-------------------------------------------------------------------------------------------------------------------------
Benchmark                                      Time             CPU   Iterations     CYCLES CYCLES/ BYTE bytes_per_second
-------------------------------------------------------------------------------------------------------------------------
ascon128a_aead_encrypt/256/32_mean           583 ns          583 ns           10   2.73022k      9.47994      471.215Mi/s
ascon128a_aead_encrypt/256/32_median         583 ns          583 ns           10   2.73024k      9.48001      471.281Mi/s
ascon128a_aead_encrypt/256/32_stddev       0.901 ns        0.895 ns           10    2.02359     7.02635m      740.431Ki/s
ascon128a_aead_encrypt/256/32_cv            0.15 %          0.15 %            10      0.07%        0.07%            0.15%
ascon128a_aead_encrypt/256/32_min            582 ns          582 ns           10   2.72776k      9.47137      470.067Mi/s
ascon128a_aead_encrypt/256/32_max            584 ns          584 ns           10    2.7344k      9.49445      472.077Mi/s
ascon80pq_aead_decrypt/256/32_mean           848 ns          848 ns           10   3.97168k      13.7906       323.85Mi/s
ascon80pq_aead_decrypt/256/32_median         847 ns          847 ns           10   3.97155k      13.7901      324.179Mi/s
ascon80pq_aead_decrypt/256/32_stddev        1.83 ns         1.82 ns           10   0.617003     2.14237m      709.473Ki/s
ascon80pq_aead_decrypt/256/32_cv            0.22 %          0.21 %            10      0.02%        0.02%            0.21%
ascon80pq_aead_decrypt/256/32_min            847 ns          847 ns           10   3.97089k      13.7878      322.397Mi/s
ascon80pq_aead_decrypt/256/32_max            852 ns          852 ns           10   3.97279k      13.7944      324.252Mi/s
ascon128a_aead_decrypt/4096/32_mean         6907 ns         6907 ns           10   32.3516k      7.83712      569.983Mi/s
ascon128a_aead_decrypt/4096/32_median       6903 ns         6903 ns           10   32.3557k       7.8381      570.313Mi/s
ascon128a_aead_decrypt/4096/32_stddev       17.6 ns         17.6 ns           10    45.2308    0.0109571      1.44855Mi/s
ascon128a_aead_decrypt/4096/32_cv           0.25 %          0.25 %            10      0.14%        0.14%            0.25%
ascon128a_aead_decrypt/4096/32_min          6887 ns         6887 ns           10   32.2759k      7.81876      566.589Mi/s
ascon128a_aead_decrypt/4096/32_max          6948 ns         6948 ns           10   32.4444k      7.85959      571.664Mi/s
ascon128_aead_encrypt/4096/32_mean         10086 ns        10085 ns           10   47.2309k      11.4416      390.351Mi/s
ascon128_aead_encrypt/4096/32_median       10080 ns        10079 ns           10   47.2328k      11.4421      390.604Mi/s
ascon128_aead_encrypt/4096/32_stddev        16.1 ns         16.3 ns           10    9.96508     2.41402m       645.38Ki/s
ascon128_aead_encrypt/4096/32_cv            0.16 %          0.16 %            10      0.02%        0.02%            0.16%
ascon128_aead_encrypt/4096/32_min          10074 ns        10074 ns           10   47.2158k      11.4379      388.908Mi/s
ascon128_aead_encrypt/4096/32_max          10123 ns        10123 ns           10   47.2476k      11.4456      390.797Mi/s
ascon_permutation<6>_mean                   21.7 ns         21.7 ns           10    101.497      2.53743      1.71883Gi/s
ascon_permutation<6>_median                 21.7 ns         21.7 ns           10    101.485      2.53713      1.71992Gi/s
ascon_permutation<6>_stddev                0.032 ns        0.032 ns           10  0.0342719     856.797u      2.62771Mi/s
ascon_permutation<6>_cv                     0.15 %          0.15 %            10      0.03%        0.03%            0.15%
ascon_permutation<6>_min                    21.6 ns         21.6 ns           10    101.478      2.53695      1.71464Gi/s
ascon_permutation<6>_max                    21.7 ns         21.7 ns           10    101.592      2.53979      1.72121Gi/s
ascon_permutation<12>_mean                  39.6 ns         39.6 ns           10    185.508       4.6377      962.926Mi/s
ascon_permutation<12>_median                39.6 ns         39.6 ns           10    185.513      4.63784      963.906Mi/s
ascon_permutation<12>_stddev               0.079 ns        0.079 ns           10   0.041601     1.04002m      1.92727Mi/s
ascon_permutation<12>_cv                    0.20 %          0.20 %            10      0.02%        0.02%            0.20%
ascon_permutation<12>_min                   39.6 ns         39.6 ns           10    185.452      4.63631       959.01Mi/s
ascon_permutation<12>_max                   39.8 ns         39.8 ns           10    185.553      4.63883      964.379Mi/s
ascon128a_aead_encrypt/64/32_mean            263 ns          263 ns           10   1.23018k      12.8143      348.335Mi/s
ascon128a_aead_encrypt/64/32_median          263 ns          263 ns           10   1.23008k      12.8133      348.488Mi/s
ascon128a_aead_encrypt/64/32_stddev        0.371 ns        0.370 ns           10   0.340605     3.54797m      501.565Ki/s
ascon128a_aead_encrypt/64/32_cv             0.14 %          0.14 %            10      0.03%        0.03%            0.14%
ascon128a_aead_encrypt/64/32_min             262 ns          262 ns           10    1.2298k      12.8105      347.496Mi/s
ascon128a_aead_encrypt/64/32_max             263 ns          263 ns           10   1.23074k      12.8203       348.89Mi/s
ascon128_aead_decrypt/64/32_mean             374 ns          374 ns           10   1.75302k      18.2606      244.728Mi/s
ascon128_aead_decrypt/64/32_median           374 ns          374 ns           10   1.75302k      18.2607      244.807Mi/s
ascon128_aead_decrypt/64/32_stddev         0.431 ns        0.433 ns           10   0.257703      2.6844m      289.127Ki/s
ascon128_aead_decrypt/64/32_cv              0.12 %          0.12 %            10      0.01%        0.01%            0.12%
ascon128_aead_decrypt/64/32_min              374 ns          374 ns           10   1.75264k      18.2567      243.959Mi/s
ascon128_aead_decrypt/64/32_max              375 ns          375 ns           10   1.75342k      18.2648      244.915Mi/s
ascon80pq_aead_decrypt/64/32_mean            375 ns          375 ns           10     1.754k      18.2709      244.463Mi/s
ascon80pq_aead_decrypt/64/32_median          374 ns          374 ns           10   1.75401k      18.2709      244.671Mi/s
ascon80pq_aead_decrypt/64/32_stddev        0.604 ns        0.595 ns           10   0.181081     1.88626m      397.178Ki/s
ascon80pq_aead_decrypt/64/32_cv             0.16 %          0.16 %            10      0.01%        0.01%            0.16%
ascon80pq_aead_decrypt/64/32_min             374 ns          374 ns           10   1.75379k      18.2686      243.587Mi/s
ascon80pq_aead_decrypt/64/32_max             376 ns          376 ns           10   1.75444k      18.2754      244.752Mi/s
ascon_prf/64/64_mean                         316 ns          316 ns           10   1.47886k      11.5536       386.46Mi/s
ascon_prf/64/64_median                       316 ns          316 ns           10   1.47856k      11.5512      386.753Mi/s
ascon_prf/64/64_stddev                     0.557 ns        0.560 ns           10   0.746104     5.82894m      701.485Ki/s
ascon_prf/64/64_cv                          0.18 %          0.18 %            10      0.05%        0.05%            0.18%
ascon_prf/64/64_min                          315 ns          315 ns           10   1.47814k       11.548       385.37Mi/s
ascon_prf/64/64_max                          317 ns          317 ns           10   1.48012k      11.5634      387.188Mi/s
ascon_prfs_verify/16_mean                   51.3 ns         51.3 ns           10    240.396      7.51238      594.626Mi/s
ascon_prfs_verify/16_median                 51.3 ns         51.3 ns           10    240.361      7.51127      594.825Mi/s
ascon_prfs_verify/16_stddev                0.097 ns        0.096 ns           10   0.279239     8.72621m      1.11445Mi/s
ascon_prfs_verify/16_cv                     0.19 %          0.19 %            10      0.12%        0.12%            0.19%
ascon_prfs_verify/16_min                    51.2 ns         51.2 ns           10    240.038       7.5012      592.665Mi/s
ascon_prfs_verify/16_max                    51.5 ns         51.5 ns           10    240.958      7.52994      595.885Mi/s
ascon_mac_verify/4096_mean                  5096 ns         5096 ns           10   23.8667k      5.78166      772.566Mi/s
ascon_mac_verify/4096_median                5096 ns         5096 ns           10   23.8678k      5.78192      772.575Mi/s
ascon_mac_verify/4096_stddev                10.0 ns         9.98 ns           10    48.6134    0.0117765      1.51182Mi/s
ascon_mac_verify/4096_cv                    0.20 %          0.20 %            10      0.20%        0.20%            0.20%
ascon_mac_verify/4096_min                   5080 ns         5080 ns           10   23.7886k      5.76274      769.735Mi/s
ascon_mac_verify/4096_max                   5115 ns         5114 ns           10   23.9392k      5.79922      775.023Mi/s
ascon_hash/1024_mean                        4682 ns         4682 ns           10   21.9285k      20.7657      215.108Mi/s
ascon_hash/1024_median                      4679 ns         4679 ns           10   21.9289k       20.766      215.251Mi/s
ascon_hash/1024_stddev                      6.82 ns         6.85 ns           10    1.29733     1.22853m      321.625Ki/s
ascon_hash/1024_cv                          0.15 %          0.15 %            10      0.01%        0.01%            0.15%
ascon_hash/1024_min                         4677 ns         4676 ns           10   21.9263k      20.7635      214.355Mi/s
ascon_hash/1024_max                         4698 ns         4698 ns           10   21.9301k      20.7671      215.352Mi/s
ascon128_aead_encrypt/64/32_mean             361 ns          361 ns           10   1.69123k      17.6169      253.723Mi/s
ascon128_aead_encrypt/64/32_median           361 ns          361 ns           10   1.69122k      17.6169      253.757Mi/s
ascon128_aead_encrypt/64/32_stddev         0.169 ns        0.168 ns           10   0.149425     1.55651m       121.09Ki/s
ascon128_aead_encrypt/64/32_cv              0.05 %          0.05 %            10      0.01%        0.01%            0.05%
ascon128_aead_encrypt/64/32_min              361 ns          361 ns           10   1.69093k      17.6139      253.442Mi/s
ascon128_aead_encrypt/64/32_max              361 ns          361 ns           10   1.69153k      17.6201      253.825Mi/s
ascon_prfs_authenticate/16_mean             44.3 ns         44.3 ns           10    207.439      6.48247      689.419Mi/s
ascon_prfs_authenticate/16_median           44.3 ns         44.3 ns           10    207.424      6.48199      689.502Mi/s
ascon_prfs_authenticate/16_stddev          0.053 ns        0.053 ns           10   0.113054     3.53294m      844.366Ki/s
ascon_prfs_authenticate/16_cv               0.12 %          0.12 %            10      0.05%        0.05%            0.12%
ascon_prfs_authenticate/16_min              44.2 ns         44.2 ns           10    207.324      6.47886      687.385Mi/s
ascon_prfs_authenticate/16_max              44.4 ns         44.4 ns           10    207.659      6.48936      690.158Mi/s
ascon_xofa/4096/64_mean                    12527 ns        12526 ns           10   58.6404k      14.0962      316.717Mi/s
ascon_xofa/4096/64_median                  12515 ns        12515 ns           10   58.6405k      14.0963      317.006Mi/s
ascon_xofa/4096/64_stddev                   26.6 ns         26.7 ns           10    9.20608       2.213m      689.003Ki/s
ascon_xofa/4096/64_cv                       0.21 %          0.21 %            10      0.02%        0.02%            0.21%
ascon_xofa/4096/64_min                     12506 ns        12505 ns           10   58.6294k      14.0936      315.086Mi/s
ascon_xofa/4096/64_max                     12591 ns        12591 ns           10   58.6625k      14.1016      317.247Mi/s
ascon_hasha/1024_mean                       3167 ns         3167 ns           10   14.8329k      14.0463      318.022Mi/s
ascon_hasha/1024_median                     3165 ns         3165 ns           10   14.8321k      14.0455      318.211Mi/s
ascon_hasha/1024_stddev                     3.58 ns         3.59 ns           10    2.51923     2.38563m      368.341Ki/s
ascon_hasha/1024_cv                         0.11 %          0.11 %            10      0.02%        0.02%            0.11%
ascon_hasha/1024_min                        3164 ns         3164 ns           10   14.8301k      14.0437      317.358Mi/s
ascon_hasha/1024_max                        3174 ns         3173 ns           10   14.8373k      14.0504      318.343Mi/s
ascon_prfs_authenticate/1_mean              51.3 ns         51.2 ns           10    239.992      14.1172      316.346Mi/s
ascon_prfs_authenticate/1_median            51.2 ns         51.2 ns           10    240.029      14.1193      316.512Mi/s
ascon_prfs_authenticate/1_stddev           0.079 ns        0.078 ns           10   0.114951     6.76182m      492.101Ki/s
ascon_prfs_authenticate/1_cv                0.15 %          0.15 %            10      0.05%        0.05%            0.15%
ascon_prfs_authenticate/1_min               51.2 ns         51.2 ns           10    239.797      14.1057      315.608Mi/s
ascon_prfs_authenticate/1_max               51.4 ns         51.4 ns           10    240.141       14.126      316.944Mi/s
ascon_mac_authenticate/1024_mean            1365 ns         1365 ns           10   6.39016k      6.14438      726.797Mi/s
ascon_mac_authenticate/1024_median          1364 ns         1363 ns           10   6.38624k      6.14062       727.68Mi/s
ascon_mac_authenticate/1024_stddev          5.07 ns         5.04 ns           10    20.6963    0.0199002      2.67735Mi/s
ascon_mac_authenticate/1024_cv              0.37 %          0.37 %            10      0.32%        0.32%            0.37%
ascon_mac_authenticate/1024_min             1359 ns         1359 ns           10   6.36335k      6.11861      721.697Mi/s
ascon_mac_authenticate/1024_max             1374 ns         1374 ns           10   6.42797k      6.18074      729.876Mi/s
ascon_mac_verify/1024_mean                  1366 ns         1366 ns           10   6.40335k      6.06378      737.215Mi/s
ascon_mac_verify/1024_median                1367 ns         1366 ns           10   6.40619k      6.06647      737.018Mi/s
ascon_mac_verify/1024_stddev                4.57 ns         4.57 ns           10    21.3835    0.0202496      2.46954Mi/s
ascon_mac_verify/1024_cv                    0.33 %          0.33 %            10      0.33%        0.33%            0.33%
ascon_mac_verify/1024_min                   1360 ns         1360 ns           10   6.37343k      6.03544      734.118Mi/s
ascon_mac_verify/1024_max                   1372 ns         1372 ns           10   6.42976k      6.08879      740.682Mi/s
ascon_hash/256_mean                         1318 ns         1318 ns           10   6.17232k      21.4317      208.451Mi/s
ascon_hash/256_median                       1317 ns         1317 ns           10   6.17229k      21.4316      208.567Mi/s
ascon_hash/256_stddev                       1.59 ns         1.57 ns           10   0.317396     1.10207m      254.873Ki/s
ascon_hash/256_cv                           0.12 %          0.12 %            10      0.01%        0.01%            0.12%
ascon_hash/256_min                          1316 ns         1316 ns           10   6.17195k      21.4304          208Mi/s
ascon_hash/256_max                          1320 ns         1320 ns           10    6.1731k      21.4344      208.646Mi/s
ascon_hasha/4096_mean                      12235 ns        12234 ns           10   57.2771k      13.8753      321.784Mi/s
ascon_hasha/4096_median                    12223 ns        12223 ns           10   57.2739k      13.8745      322.073Mi/s
ascon_hasha/4096_stddev                     19.8 ns         19.7 ns           10    12.6403     3.06208m      529.687Ki/s
ascon_hasha/4096_cv                         0.16 %          0.16 %            10      0.02%        0.02%            0.16%
ascon_hasha/4096_min                       12213 ns        12213 ns           10    57.258k      13.8706      320.931Mi/s
ascon_hasha/4096_max                       12267 ns        12267 ns           10    57.299k      13.8806      322.346Mi/s
ascon80pq_aead_encrypt/4096/32_mean        10186 ns        10185 ns           10   47.6945k      11.5539      386.515Mi/s
ascon80pq_aead_encrypt/4096/32_median      10180 ns        10180 ns           10   47.6949k       11.554      386.729Mi/s
ascon80pq_aead_encrypt/4096/32_stddev       12.2 ns         12.1 ns           10    17.8077     4.31389m      470.473Ki/s
ascon80pq_aead_encrypt/4096/32_cv           0.12 %          0.12 %            10      0.04%        0.04%            0.12%
ascon80pq_aead_encrypt/4096/32_min         10173 ns        10172 ns           10   47.6736k      11.5488      385.739Mi/s
ascon80pq_aead_encrypt/4096/32_max         10206 ns        10206 ns           10   47.7315k      11.5629      387.004Mi/s
ascon128_aead_encrypt/1024/32_mean          2679 ns         2678 ns           10   12.5395k      11.8746      376.019Mi/s
ascon128_aead_encrypt/1024/32_median        2677 ns         2677 ns           10   12.5391k      11.8741      376.167Mi/s
ascon128_aead_encrypt/1024/32_stddev        4.48 ns         4.33 ns           10    1.63451     1.54783m      621.618Ki/s
ascon128_aead_encrypt/1024/32_cv            0.17 %          0.16 %            10      0.01%        0.01%            0.16%
ascon128_aead_encrypt/1024/32_min           2674 ns         2674 ns           10   12.5377k      11.8728      375.076Mi/s
ascon128_aead_encrypt/1024/32_max           2685 ns         2685 ns           10   12.5425k      11.8774      376.576Mi/s
ascon_permutation<1>_mean                   6.69 ns         6.69 ns           10    31.3178     0.782946      5.57153Gi/s
ascon_permutation<1>_median                 6.68 ns         6.68 ns           10    31.3189     0.782974      5.57392Gi/s
ascon_permutation<1>_stddev                0.011 ns        0.011 ns           10  0.0567209     1.41802m      9.42002Mi/s
ascon_permutation<1>_cv                     0.17 %          0.17 %            10      0.18%        0.18%            0.17%
ascon_permutation<1>_min                    6.67 ns         6.67 ns           10    31.2422     0.781056      5.55684Gi/s
ascon_permutation<1>_max                    6.70 ns         6.70 ns           10    31.4141     0.785353       5.5866Gi/s
ascon_prfs_verify/1_mean                    57.4 ns         57.4 ns           10    268.955      15.8209      282.266Mi/s
ascon_prfs_verify/1_median                  57.5 ns         57.4 ns           10    268.968      15.8217      282.227Mi/s
ascon_prfs_verify/1_stddev                 0.104 ns        0.104 ns           10   0.340261    0.0200153      524.026Ki/s
ascon_prfs_verify/1_cv                      0.18 %          0.18 %            10      0.13%        0.13%            0.18%
ascon_prfs_verify/1_min                     57.3 ns         57.3 ns           10    268.514      15.7949      281.362Mi/s
ascon_prfs_verify/1_max                     57.6 ns         57.6 ns           10    269.436      15.8492      283.071Mi/s
ascon128a_aead_decrypt/64/32_mean            284 ns          284 ns           10   1.33076k      13.8621      322.306Mi/s
ascon128a_aead_decrypt/64/32_median          284 ns          284 ns           10   1.33098k      13.8644      322.453Mi/s
ascon128a_aead_decrypt/64/32_stddev        0.504 ns        0.504 ns           10   0.651693     6.78847m      583.669Ki/s
ascon128a_aead_decrypt/64/32_cv             0.18 %          0.18 %            10      0.05%        0.05%            0.18%
ascon128a_aead_decrypt/64/32_min             284 ns          284 ns           10   1.32943k      13.8482      320.723Mi/s
ascon128a_aead_decrypt/64/32_max             285 ns          285 ns           10   1.33143k      13.8691      322.734Mi/s
ascon_mac_authenticate/4096_mean            5091 ns         5091 ns           10   23.8368k      5.79689      770.287Mi/s
ascon_mac_authenticate/4096_median          5086 ns         5086 ns           10   23.8343k      5.79627      771.005Mi/s
ascon_mac_authenticate/4096_stddev          14.6 ns         14.6 ns           10       50.5    0.0122811      2.20416Mi/s
ascon_mac_authenticate/4096_cv              0.29 %          0.29 %            10      0.21%        0.21%            0.29%
ascon_mac_authenticate/4096_min             5072 ns         5072 ns           10   23.7771k      5.78238      766.433Mi/s
ascon_mac_authenticate/4096_max             5117 ns         5117 ns           10    23.945k      5.82319      773.202Mi/s
ascon80pq_aead_decrypt/1024/32_mean         2741 ns         2741 ns           10   12.8306k      12.1501      367.449Mi/s
ascon80pq_aead_decrypt/1024/32_median       2737 ns         2737 ns           10   12.8278k      12.1475      367.928Mi/s
ascon80pq_aead_decrypt/1024/32_stddev       6.37 ns         6.34 ns           10    7.65345     7.24759m      868.617Ki/s
ascon80pq_aead_decrypt/1024/32_cv           0.23 %          0.23 %            10      0.06%        0.06%            0.23%
ascon80pq_aead_decrypt/1024/32_min          2735 ns         2735 ns           10   12.8217k      12.1418      365.746Mi/s
ascon80pq_aead_decrypt/1024/32_max          2754 ns         2753 ns           10   12.8438k      12.1627      368.205Mi/s
ascon128_aead_encrypt/256/32_mean            831 ns          831 ns           10   3.86295k       13.413      330.783Mi/s
ascon128_aead_encrypt/256/32_median          825 ns          825 ns           10   3.86204k      13.4099      332.742Mi/s
ascon128_aead_encrypt/256/32_stddev         17.2 ns         17.2 ns           10    2.76152     9.58862m      6.50024Mi/s
ascon128_aead_encrypt/256/32_cv             2.07 %          2.07 %            10      0.07%        0.07%            1.97%
ascon128_aead_encrypt/256/32_min             824 ns          824 ns           10   3.86157k      13.4082      312.366Mi/s
ascon128_aead_encrypt/256/32_max             879 ns          879 ns           10   3.87069k      13.4399      333.482Mi/s
ascon_mac_authenticate/64_mean               197 ns          197 ns           10    921.057      11.5132      387.583Mi/s
ascon_mac_authenticate/64_median             197 ns          197 ns           10    921.358       11.517      387.568Mi/s
ascon_mac_authenticate/64_stddev           0.396 ns        0.416 ns           10   0.949702    0.0118713      837.983Ki/s
ascon_mac_authenticate/64_cv                0.20 %          0.21 %            10      0.10%        0.10%            0.21%
ascon_mac_authenticate/64_min                196 ns          196 ns           10    919.212      11.4902      386.077Mi/s
ascon_mac_authenticate/64_max                198 ns          198 ns           10    922.112      11.5264      388.828Mi/s
ascon_hash/64_mean                           477 ns          477 ns           10   2.23342k      23.2648      191.992Mi/s
ascon_hash/64_median                         477 ns          476 ns           10   2.23333k      23.2638      192.136Mi/s
ascon_hash/64_stddev                       0.649 ns        0.661 ns           10   0.227305     2.36776m      272.067Ki/s
ascon_hash/64_cv                            0.14 %          0.14 %            10      0.01%        0.01%            0.14%
ascon_hash/64_min                            476 ns          476 ns           10   2.23313k      23.2617      191.401Mi/s
ascon_hash/64_max                            478 ns          478 ns           10   2.23381k      23.2689      192.207Mi/s
ascon_xofa/256/64_mean                      1030 ns         1030 ns           10    4.8265k      15.0828       296.25Mi/s
ascon_xofa/256/64_median                    1030 ns         1030 ns           10   4.82651k      15.0829      296.415Mi/s
ascon_xofa/256/64_stddev                    1.03 ns         1.04 ns           10   0.158769     496.153u      306.285Ki/s
ascon_xofa/256/64_cv                        0.10 %          0.10 %            10      0.00%        0.00%            0.10%
ascon_xofa/256/64_min                       1029 ns         1029 ns           10   4.82625k       15.082      295.684Mi/s
ascon_xofa/256/64_max                       1032 ns         1032 ns           10    4.8268k      15.0838      296.471Mi/s
ascon80pq_aead_decrypt/4096/32_mean        10303 ns        10303 ns           10   48.2906k      11.6983      382.115Mi/s
ascon80pq_aead_decrypt/4096/32_median      10299 ns        10298 ns           10   48.2628k      11.6916      382.267Mi/s
ascon80pq_aead_decrypt/4096/32_stddev       14.8 ns         14.8 ns           10    72.4589     0.017553      562.287Ki/s
ascon80pq_aead_decrypt/4096/32_cv           0.14 %          0.14 %            10      0.15%        0.15%            0.14%
ascon80pq_aead_decrypt/4096/32_min         10286 ns        10286 ns           10   48.2176k      11.6806      381.179Mi/s
ascon80pq_aead_decrypt/4096/32_max         10328 ns        10328 ns           10   48.4216k        11.73      382.747Mi/s
ascon_xofa/1024/64_mean                     3332 ns         3330 ns           10   15.5835k       14.323      311.577Mi/s
ascon_xofa/1024/64_median                   3331 ns         3330 ns           10   15.5823k      14.3219      311.595Mi/s
ascon_xofa/1024/64_stddev                   6.48 ns         6.17 ns           10    2.51164      2.3085m      590.141Ki/s
ascon_xofa/1024/64_cv                       0.19 %          0.19 %            10      0.02%        0.02%            0.18%
ascon_xofa/1024/64_min                      3323 ns         3323 ns           10   15.5814k      14.3211      310.433Mi/s
ascon_xofa/1024/64_max                      3343 ns         3342 ns           10   15.5885k      14.3277       312.22Mi/s
ascon_hasha/256_mean                         902 ns          902 ns           10   4.22477k      14.6693      304.451Mi/s
ascon_hasha/256_median                       901 ns          901 ns           10   4.22477k      14.6694      304.706Mi/s
ascon_hasha/256_stddev                      1.67 ns         1.68 ns           10   0.582183     2.02147m      577.686Ki/s
ascon_hasha/256_cv                          0.19 %          0.19 %            10      0.01%        0.01%            0.19%
ascon_hasha/256_min                          901 ns          901 ns           10   4.22353k       14.665      303.046Mi/s
ascon_hasha/256_max                          906 ns          906 ns           10   4.22545k      14.6717      304.845Mi/s
ascon128a_aead_encrypt/4096/32_mean         6910 ns         6909 ns           10   32.3613k      7.83947      569.765Mi/s
ascon128a_aead_encrypt/4096/32_median       6907 ns         6907 ns           10   32.3624k      7.83973      569.995Mi/s
ascon128a_aead_encrypt/4096/32_stddev       8.11 ns         8.11 ns           10    5.69172     1.37881m      683.929Ki/s
ascon128a_aead_encrypt/4096/32_cv           0.12 %          0.12 %            10      0.02%        0.02%            0.12%
ascon128a_aead_encrypt/4096/32_min          6901 ns         6901 ns           10   32.3509k      7.83695      568.308Mi/s
ascon128a_aead_encrypt/4096/32_max          6928 ns         6927 ns           10   32.3691k      7.84135      570.489Mi/s
ascon_xofa/64/64_mean                        455 ns          455 ns           10   2.13171k       16.654       268.19Mi/s
ascon_xofa/64/64_median                      455 ns          455 ns           10   2.13165k      16.6535      268.419Mi/s
ascon_xofa/64/64_stddev                    0.673 ns        0.672 ns           10   0.125686     981.922u      404.775Ki/s
ascon_xofa/64/64_cv                         0.15 %          0.15 %            10      0.01%        0.01%            0.15%
ascon_xofa/64/64_min                         455 ns          455 ns           10   2.13159k       16.653      267.526Mi/s
ascon_xofa/64/64_max                         456 ns          456 ns           10   2.13194k      16.6558      268.497Mi/s
ascon_xof/4096/64_mean                     18863 ns        18863 ns           10    88.204k      21.2029      210.327Mi/s
ascon_xof/4096/64_median                   18823 ns        18822 ns           10   88.2028k      21.2026      210.775Mi/s
ascon_xof/4096/64_stddev                    80.8 ns         80.9 ns           10    20.0327     4.81556m      916.907Ki/s
ascon_xof/4096/64_cv                        0.43 %          0.43 %            10      0.02%        0.02%            0.43%
ascon_xof/4096/64_min                      18809 ns        18809 ns           10   88.1802k      21.1972      208.102Mi/s
ascon_xof/4096/64_max                      19064 ns        19064 ns           10   88.2348k      21.2103      210.924Mi/s
ascon_permutation<8>_mean                   27.7 ns         27.7 ns           10    129.903      3.24757       1.3434Gi/s
ascon_permutation<8>_median                 27.7 ns         27.7 ns           10    129.924      3.24809      1.34388Gi/s
ascon_permutation<8>_stddev                0.034 ns        0.034 ns           10  0.0501283     1.25321m      1.70468Mi/s
ascon_permutation<8>_cv                     0.12 %          0.12 %            10      0.04%        0.04%            0.12%
ascon_permutation<8>_min                    27.7 ns         27.7 ns           10    129.836      3.24589      1.33929Gi/s
ascon_permutation<8>_max                    27.8 ns         27.8 ns           10    129.962      3.24905      1.34501Gi/s
ascon_hash/4096_mean                       18154 ns        18153 ns           10   84.9931k      20.5894      216.866Mi/s
ascon_hash/4096_median                     18147 ns        18146 ns           10   84.9969k      20.5903      216.946Mi/s
ascon_hash/4096_stddev                      18.3 ns         17.9 ns           10    15.9394     3.86128m      219.457Ki/s
ascon_hash/4096_cv                          0.10 %          0.10 %            10      0.02%        0.02%            0.10%
ascon_hash/4096_min                        18131 ns        18131 ns           10   84.9506k      20.5791      216.486Mi/s
ascon_hash/4096_max                        18187 ns        18185 ns           10   85.0112k      20.5938       217.13Mi/s
ascon128a_aead_decrypt/256/32_mean           604 ns          604 ns           10   2.82675k       9.8151      454.784Mi/s
ascon128a_aead_decrypt/256/32_median         603 ns          603 ns           10   2.82684k      9.81541       455.15Mi/s
ascon128a_aead_decrypt/256/32_stddev        1.44 ns         1.45 ns           10    2.16866     7.53008m      1.08815Mi/s
ascon128a_aead_decrypt/256/32_cv            0.24 %          0.24 %            10      0.08%        0.08%            0.24%
ascon128a_aead_decrypt/256/32_min            602 ns          602 ns           10   2.82355k      9.80398       452.47Mi/s
ascon128a_aead_decrypt/256/32_max            607 ns          607 ns           10   2.83035k       9.8276      455.894Mi/s
ascon128a_aead_decrypt/1024/32_mean         1862 ns         1862 ns           10   8.71715k      8.25488      540.906Mi/s
ascon128a_aead_decrypt/1024/32_median       1861 ns         1861 ns           10   8.71643k      8.25419      541.141Mi/s
ascon128a_aead_decrypt/1024/32_stddev       3.13 ns         3.12 ns           10    5.02203     4.75571m      927.552Ki/s
ascon128a_aead_decrypt/1024/32_cv           0.17 %          0.17 %            10      0.06%        0.06%            0.17%
ascon128a_aead_decrypt/1024/32_min          1859 ns         1859 ns           10   8.70915k       8.2473      539.329Mi/s
ascon128a_aead_decrypt/1024/32_max          1867 ns         1867 ns           10    8.7249k      8.26221      541.744Mi/s
ascon128a_aead_encrypt/1024/32_mean         1847 ns         1847 ns           10   8.65324k      8.19435      545.216Mi/s
ascon128a_aead_encrypt/1024/32_median       1847 ns         1847 ns           10   8.65273k      8.19387      545.388Mi/s
ascon128a_aead_encrypt/1024/32_stddev       1.86 ns         1.80 ns           10    4.47625     4.23888m      544.224Ki/s
ascon128a_aead_encrypt/1024/32_cv           0.10 %          0.10 %            10      0.05%        0.05%            0.10%
ascon128a_aead_encrypt/1024/32_min          1845 ns         1845 ns           10   8.64628k      8.18777      544.204Mi/s
ascon128a_aead_encrypt/1024/32_max          1851 ns         1851 ns           10   8.66342k        8.204      545.747Mi/s
ascon80pq_aead_encrypt/1024/32_mean         2681 ns         2681 ns           10   12.5584k      11.8924      375.609Mi/s
ascon80pq_aead_encrypt/1024/32_median       2681 ns         2681 ns           10   12.5594k      11.8934      375.677Mi/s
ascon80pq_aead_encrypt/1024/32_stddev       2.83 ns         2.83 ns           10    3.01172       2.852m      405.798Ki/s
ascon80pq_aead_encrypt/1024/32_cv           0.11 %          0.11 %            10      0.02%        0.02%            0.11%
ascon80pq_aead_encrypt/1024/32_min          2678 ns         2678 ns           10   12.5532k      11.8875       374.92Mi/s
ascon80pq_aead_encrypt/1024/32_max          2686 ns         2686 ns           10   12.5622k       11.896      376.014Mi/s
ascon_prf/256/64_mean                        530 ns          530 ns           10   2.48466k      7.76457      575.469Mi/s
ascon_prf/256/64_median                      530 ns          530 ns           10   2.48501k      7.76564      575.738Mi/s
ascon_prf/256/64_stddev                    0.671 ns        0.673 ns           10     1.2669     3.95906m      746.588Ki/s
ascon_prf/256/64_cv                         0.13 %          0.13 %            10      0.05%        0.05%            0.13%
ascon_prf/256/64_min                         529 ns          529 ns           10   2.48156k      7.75489       574.02Mi/s
ascon_prf/256/64_max                         532 ns          532 ns           10   2.48581k      7.76817      576.441Mi/s
ascon80pq_aead_encrypt/64/32_mean            340 ns          340 ns           10   1.58961k      16.5585      269.633Mi/s
ascon80pq_aead_encrypt/64/32_median          340 ns          339 ns           10   1.58956k      16.5579      269.682Mi/s
ascon80pq_aead_encrypt/64/32_stddev        0.483 ns        0.473 ns           10   0.261329     2.72218m      384.221Ki/s
ascon80pq_aead_encrypt/64/32_cv             0.14 %          0.14 %            10      0.02%        0.02%            0.14%
ascon80pq_aead_encrypt/64/32_min             339 ns          339 ns           10   1.58928k       16.555      268.956Mi/s
ascon80pq_aead_encrypt/64/32_max             340 ns          340 ns           10   1.59016k      16.5641        270.1Mi/s
ascon_xof/256/64_mean                       1519 ns         1519 ns           10    7.1128k      22.2275       200.93Mi/s
ascon_xof/256/64_median                     1517 ns         1517 ns           10   7.11278k      22.2274      201.163Mi/s
ascon_xof/256/64_stddev                     2.80 ns         2.77 ns           10   0.465721     1.45538m      374.978Ki/s
ascon_xof/256/64_cv                         0.18 %          0.18 %            10      0.01%        0.01%            0.18%
ascon_xof/256/64_min                        1517 ns         1517 ns           10   7.11197k      22.2249      200.219Mi/s
ascon_xof/256/64_max                        1524 ns         1524 ns           10   7.11357k      22.2299      201.187Mi/s
ascon128_aead_decrypt/4096/32_mean         10361 ns        10361 ns           10   48.4704k      11.7419      379.967Mi/s
ascon128_aead_decrypt/4096/32_median       10365 ns        10365 ns           10   48.4303k      11.7322      379.825Mi/s
ascon128_aead_decrypt/4096/32_stddev        24.3 ns         24.4 ns           10    88.0863    0.0213387      916.649Ki/s
ascon128_aead_decrypt/4096/32_cv            0.23 %          0.24 %            10      0.18%        0.18%            0.24%
ascon128_aead_decrypt/4096/32_min          10331 ns        10330 ns           10   48.3873k      11.7217      378.731Mi/s
ascon128_aead_decrypt/4096/32_max          10395 ns        10395 ns           10   48.6071k       11.775      381.109Mi/s
ascon_mac_verify/64_mean                     202 ns          202 ns           10    945.701      9.85105      453.208Mi/s
ascon_mac_verify/64_median                   202 ns          202 ns           10    945.853      9.85264      453.334Mi/s
ascon_mac_verify/64_stddev                 0.344 ns        0.343 ns           10   0.732957     7.63497m      786.773Ki/s
ascon_mac_verify/64_cv                      0.17 %          0.17 %            10      0.08%        0.08%            0.17%
ascon_mac_verify/64_min                      202 ns          202 ns           10    944.497      9.83851      451.901Mi/s
ascon_mac_verify/64_max                      203 ns          203 ns           10    946.725      9.86172      454.293Mi/s
ascon_mac_verify/256_mean                    434 ns          434 ns           10   2.03427k      7.06342      632.682Mi/s
ascon_mac_verify/256_median                  434 ns          434 ns           10     2.033k      7.05904      633.129Mi/s
ascon_mac_verify/256_stddev                0.749 ns        0.702 ns           10     2.9101    0.0101045      1.02218Mi/s
ascon_mac_verify/256_cv                     0.17 %          0.16 %            10      0.14%        0.14%            0.16%
ascon_mac_verify/256_min                     433 ns          433 ns           10    2.0319k      7.05522      630.667Mi/s
ascon_mac_verify/256_max                     436 ns          436 ns           10    2.0418k      7.08957      633.629Mi/s
ascon_prf/1024/64_mean                      1387 ns         1387 ns           10   6.49455k      5.96925      747.987Mi/s
ascon_prf/1024/64_median                    1387 ns         1387 ns           10   6.49606k      5.97064      748.236Mi/s
ascon_prf/1024/64_stddev                    2.74 ns         2.75 ns           10    5.70791     5.24624m      1.48142Mi/s
ascon_prf/1024/64_cv                        0.20 %          0.20 %            10      0.09%        0.09%            0.20%
ascon_prf/1024/64_min                       1382 ns         1382 ns           10   6.48154k       5.9573      745.898Mi/s
ascon_prf/1024/64_max                       1391 ns         1391 ns           10   6.50289k      5.97692      750.572Mi/s
ascon_hasha/64_mean                          335 ns          335 ns           10    1.5682k      16.3354      273.305Mi/s
ascon_hasha/64_median                        335 ns          335 ns           10   1.56818k      16.3352      273.542Mi/s
ascon_hasha/64_stddev                      0.649 ns        0.645 ns           10   0.156033     1.62534m      538.206Ki/s
ascon_hasha/64_cv                           0.19 %          0.19 %            10      0.01%        0.01%            0.19%
ascon_hasha/64_min                           334 ns          334 ns           10   1.56788k      16.3321      272.353Mi/s
ascon_hasha/64_max                           336 ns          336 ns           10   1.56843k      16.3378      273.784Mi/s
ascon_xof/64/64_mean                         653 ns          653 ns           10   3.05929k      23.9007      186.883Mi/s
ascon_xof/64/64_median                       653 ns          653 ns           10   3.05891k      23.8977      186.918Mi/s
ascon_xof/64/64_stddev                     0.762 ns        0.752 ns           10    1.34015    0.0104699      220.139Ki/s
ascon_xof/64/64_cv                          0.12 %          0.12 %            10      0.04%        0.04%            0.12%
ascon_xof/64/64_min                          652 ns          652 ns           10    3.0582k      23.8922      186.477Mi/s
ascon_xof/64/64_max                          655 ns          655 ns           10   3.06301k      23.9298        187.1Mi/s
ascon_mac_authenticate/256_mean              429 ns          429 ns           10   2.01021k      7.39048      604.805Mi/s
ascon_mac_authenticate/256_median            429 ns          429 ns           10   2.01013k      7.39019      604.752Mi/s
ascon_mac_authenticate/256_stddev          0.720 ns        0.727 ns           10    3.29322    0.0121074      1.02674Mi/s
ascon_mac_authenticate/256_cv               0.17 %          0.17 %            10      0.16%        0.16%            0.17%
ascon_mac_authenticate/256_min               427 ns          427 ns           10   2.00265k      7.36268      603.503Mi/s
ascon_mac_authenticate/256_max               430 ns          430 ns           10   2.01528k      7.40913      607.191Mi/s
ascon_prfs_verify/4_mean                    57.1 ns         57.1 ns           10    267.452      13.3726      333.965Mi/s
ascon_prfs_verify/4_median                  57.1 ns         57.1 ns           10    267.638      13.3819      333.931Mi/s
ascon_prfs_verify/4_stddev                 0.122 ns        0.122 ns           10   0.502648    0.0251324      731.602Ki/s
ascon_prfs_verify/4_cv                      0.21 %          0.21 %            10      0.19%        0.19%            0.21%
ascon_prfs_verify/4_min                     56.9 ns         56.9 ns           10    266.466      13.3233      332.892Mi/s
ascon_prfs_verify/4_max                     57.3 ns         57.3 ns           10    268.145      13.4073      334.978Mi/s
ascon128_aead_decrypt/1024/32_mean          2749 ns         2749 ns           10   12.8714k      12.1888      366.317Mi/s
ascon128_aead_decrypt/1024/32_median        2748 ns         2748 ns           10   12.8701k      12.1876      366.453Mi/s
ascon128_aead_decrypt/1024/32_stddev        4.39 ns         4.43 ns           10    9.29964     8.80647m       603.36Ki/s
ascon128_aead_decrypt/1024/32_cv            0.16 %          0.16 %            10      0.07%        0.07%            0.16%
ascon128_aead_decrypt/1024/32_min           2744 ns         2744 ns           10   12.8598k      12.1779      365.286Mi/s
ascon128_aead_decrypt/1024/32_max           2757 ns         2757 ns           10   12.8866k      12.2032      367.053Mi/s
ascon_xof/1024/64_mean                      4984 ns         4984 ns           10   23.3291k      21.4422      208.207Mi/s
ascon_xof/1024/64_median                    4982 ns         4981 ns           10   23.3278k       21.441      208.318Mi/s
ascon_xof/1024/64_stddev                    10.5 ns         10.5 ns           10    4.52552     4.15948m      448.444Ki/s
ascon_xof/1024/64_cv                        0.21 %          0.21 %            10      0.02%        0.02%            0.21%
ascon_xof/1024/64_min                       4975 ns         4975 ns           10   23.3249k      21.4383        207.1Mi/s
ascon_xof/1024/64_max                       5010 ns         5010 ns           10   23.3395k      21.4517      208.574Mi/s
ascon80pq_aead_encrypt/256/32_mean           808 ns          808 ns           10   3.78258k       13.134      340.039Mi/s
ascon80pq_aead_encrypt/256/32_median         807 ns          807 ns           10   3.78266k      13.1342      340.296Mi/s
ascon80pq_aead_encrypt/256/32_stddev        1.20 ns         1.20 ns           10   0.203471     706.496u      517.765Ki/s
ascon80pq_aead_encrypt/256/32_cv            0.15 %          0.15 %            10      0.01%        0.01%            0.15%
ascon80pq_aead_encrypt/256/32_min            807 ns          807 ns           10   3.78226k      13.1328      339.209Mi/s
ascon80pq_aead_encrypt/256/32_max            810 ns          810 ns           10    3.7828k      13.1347       340.46Mi/s
ascon128_aead_decrypt/256/32_mean            849 ns          849 ns           10   3.97819k      13.8132      323.427Mi/s
ascon128_aead_decrypt/256/32_median          849 ns          849 ns           10   3.97785k       13.812      323.618Mi/s
ascon128_aead_decrypt/256/32_stddev         1.12 ns         1.12 ns           10     0.6633     2.30313m      434.992Ki/s
ascon128_aead_decrypt/256/32_cv             0.13 %          0.13 %            10      0.02%        0.02%            0.13%
ascon128_aead_decrypt/256/32_min             848 ns          848 ns           10   3.97757k       13.811      322.456Mi/s
ascon128_aead_decrypt/256/32_max             852 ns          852 ns           10   3.97937k      13.8173       323.73Mi/s
ascon_prf/4096/64_mean                      4818 ns         4817 ns           10   22.5586k      5.42275       823.54Mi/s
ascon_prf/4096/64_median                    4813 ns         4813 ns           10   22.5605k       5.4232      824.286Mi/s
ascon_prf/4096/64_stddev                    8.78 ns         8.76 ns           10    29.2276     7.02587m      1.49528Mi/s
ascon_prf/4096/64_cv                        0.18 %          0.18 %            10      0.13%        0.13%            0.18%
ascon_prf/4096/64_min                       4806 ns         4806 ns           10   22.5135k       5.4119      820.974Mi/s
ascon_prf/4096/64_max                       4832 ns         4832 ns           10   22.5988k       5.4324      825.498Mi/s
ascon_prfs_authenticate/4_mean              51.9 ns         51.9 ns           10    243.032      12.1516      367.346Mi/s
ascon_prfs_authenticate/4_median            51.9 ns         51.9 ns           10    242.998      12.1499       367.55Mi/s
ascon_prfs_authenticate/4_stddev           0.114 ns        0.113 ns           10   0.202861    0.0101431      817.607Ki/s
ascon_prfs_authenticate/4_cv                0.22 %          0.22 %            10      0.08%        0.08%            0.22%
ascon_prfs_authenticate/4_min               51.8 ns         51.8 ns           10    242.804      12.1402      365.629Mi/s
ascon_prfs_authenticate/4_max               52.2 ns         52.2 ns           10    243.485      12.1743       368.22Mi/s
```

### On ARM Cortex-A72 ( i.e. Raspberry Pi 4B )

Compiled with **gcc version 13.2.0 (Ubuntu 13.2.0-4ubuntu3).**

```bash
$ uname -srm
Linux 6.5.0-1009-raspi aarch64
```

```bash
2024-02-04T15:14:17+04:00
Running ./build/perfs/perf.out
Run on (4 X 1800 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x4)
  L1 Instruction 48 KiB (x4)
  L2 Unified 1024 KiB (x1)
Load Average: 18.33, 12.37, 5.86
-------------------------------------------------------------------------------------------------------------------------
Benchmark                                      Time             CPU   Iterations     CYCLES CYCLES/ BYTE bytes_per_second
-------------------------------------------------------------------------------------------------------------------------
ascon128a_aead_decrypt/4096/32_mean        26659 ns        26641 ns           10   47.8582k      11.5935      147.773Mi/s
ascon128a_aead_decrypt/4096/32_median      26661 ns        26635 ns           10   47.8025k      11.5801      147.807Mi/s
ascon128a_aead_decrypt/4096/32_stddev       78.4 ns         74.9 ns           10    137.319    0.0332651      423.803Ki/s
ascon128a_aead_decrypt/4096/32_cv           0.29 %          0.28 %            10      0.29%        0.29%            0.28%
ascon128a_aead_decrypt/4096/32_min         26578 ns        26577 ns           10   47.7726k      11.5728      146.739Mi/s
ascon128a_aead_decrypt/4096/32_max         26835 ns        26828 ns           10   48.2191k       11.681      148.126Mi/s
ascon_permutation<12>_mean                   119 ns          119 ns           10    213.514      5.33784      320.945Mi/s
ascon_permutation<12>_median                 119 ns          119 ns           10    213.761      5.34402      320.765Mi/s
ascon_permutation<12>_stddev               0.310 ns        0.305 ns           10   0.615609    0.0153902      843.918Ki/s
ascon_permutation<12>_cv                    0.26 %          0.26 %            10      0.29%        0.29%            0.26%
ascon_permutation<12>_min                    119 ns          118 ns           10    212.526      5.31315      319.679Mi/s
ascon_permutation<12>_max                    120 ns          119 ns           10    214.016       5.3504      322.078Mi/s
ascon_mac_verify/1024_mean                  4685 ns         4683 ns           10   8.41575k      7.96946      215.046Mi/s
ascon_mac_verify/1024_median                4684 ns         4682 ns           10   8.41343k      7.96727       215.11Mi/s
ascon_mac_verify/1024_stddev                7.81 ns         8.37 ns           10     15.944    0.0150985      393.549Ki/s
ascon_mac_verify/1024_cv                    0.17 %          0.18 %            10      0.19%        0.19%            0.18%
ascon_mac_verify/1024_min                   4673 ns         4672 ns           10   8.39298k       7.9479      214.431Mi/s
ascon_mac_verify/1024_max                   4698 ns         4697 ns           10   8.44078k      7.99317      215.542Mi/s
ascon_mac_authenticate/256_mean             1468 ns         1468 ns           10    2.6383k      9.69962      176.703Mi/s
ascon_mac_authenticate/256_median           1468 ns         1468 ns           10   2.63739k      9.69628      176.759Mi/s
ascon_mac_authenticate/256_stddev           3.06 ns         2.97 ns           10    5.14905    0.0189303      365.506Ki/s
ascon_mac_authenticate/256_cv               0.21 %          0.20 %            10      0.20%        0.20%            0.20%
ascon_mac_authenticate/256_min              1464 ns         1464 ns           10   2.63194k      9.67625      176.048Mi/s
ascon_mac_authenticate/256_max              1474 ns         1473 ns           10   2.64756k      9.73367      177.172Mi/s
ascon128a_aead_decrypt/256/32_mean          2223 ns         2222 ns           10   3.99141k       13.859       123.61Mi/s
ascon128a_aead_decrypt/256/32_median        2222 ns         2221 ns           10   3.99155k      13.8595      123.667Mi/s
ascon128a_aead_decrypt/256/32_stddev        4.14 ns         2.53 ns           10   0.918458     3.18909m      144.175Ki/s
ascon128a_aead_decrypt/256/32_cv            0.19 %          0.11 %            10      0.02%        0.02%            0.11%
ascon128a_aead_decrypt/256/32_min           2220 ns         2219 ns           10   3.98957k      13.8527      123.351Mi/s
ascon128a_aead_decrypt/256/32_max           2231 ns         2227 ns           10   3.99242k      13.8626      123.748Mi/s
ascon_hasha/1024_mean                      10732 ns        10727 ns           10   19.2737k      18.2516      93.8816Mi/s
ascon_hasha/1024_median                    10727 ns        10724 ns           10   19.2733k      18.2512      93.9132Mi/s
ascon_hasha/1024_stddev                     13.1 ns         8.06 ns           10   0.867178     821.191u       72.154Ki/s
ascon_hasha/1024_cv                         0.12 %          0.08 %            10      0.00%        0.00%            0.08%
ascon_hasha/1024_min                       10723 ns        10721 ns           10    19.273k       18.251      93.7443Mi/s
ascon_hasha/1024_max                       10760 ns        10743 ns           10   19.2757k      18.2535       93.932Mi/s
ascon_hash/4096_mean                       60887 ns        60846 ns           10   109.304k      26.4788      64.7005Mi/s
ascon_hash/4096_median                     60866 ns        60834 ns           10   109.306k      26.4791      64.7129Mi/s
ascon_hash/4096_stddev                      77.5 ns         44.4 ns           10    12.3617     2.99461m      48.3581Ki/s
ascon_hash/4096_cv                          0.13 %          0.07 %            10      0.01%        0.01%            0.07%
ascon_hash/4096_min                        60819 ns        60805 ns           10   109.288k      26.4747         64.6Mi/s
ascon_hash/4096_max                        61056 ns        60941 ns           10   109.318k       26.482      64.7439Mi/s
ascon_prfs_authenticate/1_mean               161 ns          161 ns           10    289.027      17.0016      100.696Mi/s
ascon_prfs_authenticate/1_median             161 ns          161 ns           10    289.016      17.0009      100.794Mi/s
ascon_prfs_authenticate/1_stddev           0.584 ns        0.392 ns           10  0.0262356     1.54327m      249.768Ki/s
ascon_prfs_authenticate/1_cv                0.36 %          0.24 %            10      0.01%        0.01%            0.24%
ascon_prfs_authenticate/1_min                161 ns          161 ns           10    289.012      17.0007      100.035Mi/s
ascon_prfs_authenticate/1_max                163 ns          162 ns           10    289.098      17.0058      100.828Mi/s
ascon80pq_aead_decrypt/1024/32_mean         7533 ns         7530 ns           10   13.5312k      12.8136      133.741Mi/s
ascon80pq_aead_decrypt/1024/32_median       7530 ns         7529 ns           10   13.5332k      12.8156      133.759Mi/s
ascon80pq_aead_decrypt/1024/32_stddev       5.52 ns         2.77 ns           10    2.99788      2.8389m      50.2877Ki/s
ascon80pq_aead_decrypt/1024/32_cv           0.07 %          0.04 %            10      0.02%        0.02%            0.04%
ascon80pq_aead_decrypt/1024/32_min          7529 ns         7527 ns           10   13.5275k      12.8101      133.655Mi/s
ascon80pq_aead_decrypt/1024/32_max          7544 ns         7535 ns           10   13.5338k      12.8161      133.787Mi/s
ascon_xofa/256/64_mean                      3443 ns         3442 ns           10    6.1854k      19.3294      88.6581Mi/s
ascon_xofa/256/64_median                    3442 ns         3441 ns           10   6.18535k      19.3292      88.6767Mi/s
ascon_xofa/256/64_stddev                    3.12 ns         2.03 ns           10   0.107035     334.485u      53.5191Ki/s
ascon_xofa/256/64_cv                        0.09 %          0.06 %            10      0.00%        0.00%            0.06%
ascon_xofa/256/64_min                       3441 ns         3441 ns           10   6.18534k      19.3292      88.5178Mi/s
ascon_xofa/256/64_max                       3452 ns         3448 ns           10   6.18569k      19.3303      88.6939Mi/s
ascon_hasha/64_mean                         1160 ns         1159 ns           10   2.08312k      21.6992      78.9784Mi/s
ascon_hasha/64_median                       1159 ns         1159 ns           10   2.08312k      21.6991       78.996Mi/s
ascon_hasha/64_stddev                       1.43 ns        0.776 ns           10  0.0337339     351.395u       54.044Ki/s
ascon_hasha/64_cv                           0.12 %          0.07 %            10      0.00%        0.00%            0.07%
ascon_hasha/64_min                          1159 ns         1159 ns           10   2.08309k      21.6988      78.8331Mi/s
ascon_hasha/64_max                          1164 ns         1161 ns           10   2.08321k      21.7001      79.0078Mi/s
ascon128_aead_decrypt/64/32_mean            1048 ns         1047 ns           10    1.8781k      19.5635      87.4218Mi/s
ascon128_aead_decrypt/64/32_median          1046 ns         1045 ns           10   1.87802k      19.5627      87.5944Mi/s
ascon128_aead_decrypt/64/32_stddev          4.73 ns         3.86 ns           10   0.210532     2.19304m      327.984Ki/s
ascon128_aead_decrypt/64/32_cv              0.45 %          0.37 %            10      0.01%        0.01%            0.37%
ascon128_aead_decrypt/64/32_min             1045 ns         1045 ns           10   1.87788k      19.5613      86.5968Mi/s
ascon128_aead_decrypt/64/32_max             1060 ns         1057 ns           10   1.87844k      19.5671      87.6292Mi/s
ascon_prfs_verify/16_mean                    204 ns          204 ns           10    366.012      11.4379      149.763Mi/s
ascon_prfs_verify/16_median                  204 ns          204 ns           10    366.018      11.4381      149.769Mi/s
ascon_prfs_verify/16_stddev                0.214 ns        0.148 ns           10  0.0433161     1.35363m      111.487Ki/s
ascon_prfs_verify/16_cv                     0.11 %          0.07 %            10      0.01%        0.01%            0.07%
ascon_prfs_verify/16_min                     204 ns          204 ns           10    365.893      11.4342      149.556Mi/s
ascon_prfs_verify/16_max                     204 ns          204 ns           10    366.046      11.4389      149.884Mi/s
ascon_mac_authenticate/1024_mean            4652 ns         4649 ns           10   8.33573k      8.01512      213.338Mi/s
ascon_mac_authenticate/1024_median          4648 ns         4645 ns           10   8.32215k      8.00206      213.536Mi/s
ascon_mac_authenticate/1024_stddev          24.5 ns         21.9 ns           10    24.8572    0.0239012      1.00384Mi/s
ascon_mac_authenticate/1024_cv              0.53 %          0.47 %            10      0.30%        0.30%            0.47%
ascon_mac_authenticate/1024_min             4625 ns         4624 ns           10   8.31201k      7.99231      211.619Mi/s
ascon_mac_authenticate/1024_max             4697 ns         4687 ns           10    8.3779k      8.05568      214.472Mi/s
ascon80pq_aead_encrypt/64/32_mean           1002 ns         1001 ns           10   1.79824k      18.7316        91.42Mi/s
ascon80pq_aead_encrypt/64/32_median         1001 ns         1001 ns           10   1.79739k      18.7228      91.4877Mi/s
ascon80pq_aead_encrypt/64/32_stddev         3.69 ns         2.58 ns           10    2.30936    0.0240559      240.414Ki/s
ascon80pq_aead_encrypt/64/32_cv             0.37 %          0.26 %            10      0.13%        0.13%            0.26%
ascon80pq_aead_encrypt/64/32_min             999 ns          999 ns           10     1.796k      18.7084      90.8685Mi/s
ascon80pq_aead_encrypt/64/32_max            1011 ns         1008 ns           10   1.80279k      18.7791      91.6189Mi/s
ascon128a_aead_encrypt/4096/32_mean        26096 ns        26085 ns           10   46.8721k      11.3547       150.92Mi/s
ascon128a_aead_encrypt/4096/32_median      26070 ns        26066 ns           10   46.8382k      11.3465      151.031Mi/s
ascon128a_aead_encrypt/4096/32_stddev       55.7 ns         54.4 ns           10    100.812    0.0244215       321.02Ki/s
ascon128a_aead_encrypt/4096/32_cv           0.21 %          0.21 %            10      0.22%        0.22%            0.21%
ascon128a_aead_encrypt/4096/32_min         26058 ns        26055 ns           10   46.8358k      11.3459      150.052Mi/s
ascon128a_aead_encrypt/4096/32_max         26243 ns        26236 ns           10   47.1583k       11.424      151.096Mi/s
ascon_mac_verify/256_mean                   1510 ns         1510 ns           10   2.71235k      9.41788      181.931Mi/s
ascon_mac_verify/256_median                 1510 ns         1509 ns           10   2.71034k      9.41089      181.964Mi/s
ascon_mac_verify/256_stddev                 2.66 ns         2.63 ns           10    5.45453    0.0189393       324.88Ki/s
ascon_mac_verify/256_cv                     0.18 %          0.17 %            10      0.20%        0.20%            0.17%
ascon_mac_verify/256_min                    1507 ns         1506 ns           10   2.70633k      9.39699      181.428Mi/s
ascon_mac_verify/256_max                    1514 ns         1514 ns           10   2.72133k      9.44905      182.345Mi/s
ascon_hash/1024_mean                       15737 ns        15731 ns           10   28.2679k      26.7688      64.0188Mi/s
ascon_hash/1024_median                     15734 ns        15729 ns           10   28.2696k      26.7704      64.0268Mi/s
ascon_hash/1024_stddev                      17.6 ns         11.2 ns           10    10.1488     9.61064m      46.7665Ki/s
ascon_hash/1024_cv                          0.11 %          0.07 %            10      0.04%        0.04%            0.07%
ascon_hash/1024_min                        15723 ns        15720 ns           10   28.2554k       26.757      63.9034Mi/s
ascon_hash/1024_max                        15785 ns        15759 ns           10   28.2877k      26.7876      64.0636Mi/s
ascon128_aead_decrypt/1024/32_mean          7363 ns         7358 ns           10   13.2176k      12.5166      136.867Mi/s
ascon128_aead_decrypt/1024/32_median        7359 ns         7356 ns           10   13.2166k      12.5157      136.899Mi/s
ascon128_aead_decrypt/1024/32_stddev        10.6 ns         7.00 ns           10    2.45594      2.3257m      133.218Ki/s
ascon128_aead_decrypt/1024/32_cv            0.14 %          0.10 %            10      0.02%        0.02%            0.10%
ascon128_aead_decrypt/1024/32_min           7352 ns         7352 ns           10   13.2155k      12.5147      136.547Mi/s
ascon128_aead_decrypt/1024/32_max           7388 ns         7375 ns           10   13.2236k      12.5223      136.985Mi/s
ascon80pq_aead_decrypt/4096/32_mean        28215 ns        28207 ns           10   50.6935k      12.2804      139.566Mi/s
ascon80pq_aead_decrypt/4096/32_median      28204 ns        28192 ns           10    50.659k      12.2721      139.642Mi/s
ascon80pq_aead_decrypt/4096/32_stddev       36.7 ns         34.4 ns           10    58.6679    0.0142122      174.179Ki/s
ascon80pq_aead_decrypt/4096/32_cv           0.13 %          0.12 %            10      0.12%        0.12%            0.12%
ascon80pq_aead_decrypt/4096/32_min         28185 ns        28181 ns           10   50.6519k      12.2703      139.222Mi/s
ascon80pq_aead_decrypt/4096/32_max         28281 ns        28277 ns           10   50.8167k      12.3102      139.697Mi/s
ascon128_aead_encrypt/64/32_mean             985 ns          984 ns           10   1.76639k      18.3999      93.0275Mi/s
ascon128_aead_encrypt/64/32_median           983 ns          983 ns           10   1.76431k      18.3782      93.1664Mi/s
ascon128_aead_encrypt/64/32_stddev          4.65 ns         3.93 ns           10     6.3378    0.0660188       378.15Ki/s
ascon128_aead_encrypt/64/32_cv              0.47 %          0.40 %            10      0.36%        0.36%            0.40%
ascon128_aead_encrypt/64/32_min              982 ns          981 ns           10   1.76417k      18.3768      92.2004Mi/s
ascon128_aead_encrypt/64/32_max              994 ns          993 ns           10   1.78442k      18.5877      93.2845Mi/s
ascon_prfs_authenticate/16_mean              166 ns          166 ns           10    298.011      9.31285      183.917Mi/s
ascon_prfs_authenticate/16_median            166 ns          166 ns           10    298.015      9.31296      184.026Mi/s
ascon_prfs_authenticate/16_stddev          0.287 ns        0.177 ns           10  0.0228232     713.225u      201.229Ki/s
ascon_prfs_authenticate/16_cv               0.17 %          0.11 %            10      0.01%        0.01%            0.11%
ascon_prfs_authenticate/16_min               166 ns          166 ns           10    297.955      9.31109      183.645Mi/s
ascon_prfs_authenticate/16_max               166 ns          166 ns           10    298.034      9.31357      184.129Mi/s
ascon80pq_aead_encrypt/1024/32_mean         7227 ns         7225 ns           10   12.9822k      12.2937      139.396Mi/s
ascon80pq_aead_encrypt/1024/32_median       7226 ns         7224 ns           10   12.9807k      12.2924        139.4Mi/s
ascon80pq_aead_encrypt/1024/32_stddev       3.43 ns         2.71 ns           10    4.97417     4.71039m      53.5306Ki/s
ascon80pq_aead_encrypt/1024/32_cv           0.05 %          0.04 %            10      0.04%        0.04%            0.04%
ascon80pq_aead_encrypt/1024/32_min          7221 ns         7220 ns           10   12.9784k      12.2902      139.271Mi/s
ascon80pq_aead_encrypt/1024/32_max          7233 ns         7231 ns           10   12.9945k      12.3054      139.482Mi/s
ascon128_aead_encrypt/4096/32_mean         26854 ns        26829 ns           10   48.1693k      11.6689      146.737Mi/s
ascon128_aead_encrypt/4096/32_median       26829 ns        26815 ns           10   48.1668k      11.6683      146.814Mi/s
ascon128_aead_encrypt/4096/32_stddev        58.2 ns         35.6 ns           10    11.4539     2.77468m      199.447Ki/s
ascon128_aead_encrypt/4096/32_cv            0.22 %          0.13 %            10      0.02%        0.02%            0.13%
ascon128_aead_encrypt/4096/32_min          26800 ns        26795 ns           10   48.1594k      11.6665      146.384Mi/s
ascon128_aead_encrypt/4096/32_max          26955 ns        26893 ns           10   48.1974k      11.6757      146.924Mi/s
ascon80pq_aead_encrypt/4096/32_mean        27135 ns        27118 ns           10   48.7072k      11.7992      145.172Mi/s
ascon80pq_aead_encrypt/4096/32_median      27104 ns        27098 ns           10      48.7k      11.7975      145.279Mi/s
ascon80pq_aead_encrypt/4096/32_stddev       90.1 ns         57.4 ns           10    19.2292     4.65822m      312.829Ki/s
ascon80pq_aead_encrypt/4096/32_cv           0.33 %          0.21 %            10      0.04%        0.04%            0.21%
ascon80pq_aead_encrypt/4096/32_min         27097 ns        27093 ns           10    48.698k       11.797      144.316Mi/s
ascon80pq_aead_encrypt/4096/32_max         27389 ns        27279 ns           10   48.7608k      11.8122      145.305Mi/s
ascon_xofa/1024/64_mean                    11128 ns        11117 ns           10   19.9535k      18.3396      93.3382Mi/s
ascon_xofa/1024/64_median                  11117 ns        11111 ns           10   19.9501k      18.3365       93.382Mi/s
ascon_xofa/1024/64_stddev                   31.5 ns         19.9 ns           10    8.03281      7.3831m      170.693Ki/s
ascon_xofa/1024/64_cv                       0.28 %          0.18 %            10      0.04%        0.04%            0.18%
ascon_xofa/1024/64_min                     11100 ns        11097 ns           10   19.9462k      18.3329      92.9413Mi/s
ascon_xofa/1024/64_max                     11204 ns        11164 ns           10   19.9667k      18.3517      93.5018Mi/s
ascon_xofa/4096/64_mean                    41777 ns        41740 ns           10   74.8723k      17.9981      95.0492Mi/s
ascon_xofa/4096/64_median                  41669 ns        41659 ns           10   74.8641k      17.9962      95.2322Mi/s
ascon_xofa/4096/64_stddev                    275 ns          220 ns           10    13.2602     3.18755m      507.507Ki/s
ascon_xofa/4096/64_cv                       0.66 %          0.53 %            10      0.02%        0.02%            0.52%
ascon_xofa/4096/64_min                     41649 ns        41645 ns           10   74.8621k      17.9957      93.6647Mi/s
ascon_xofa/4096/64_max                     42532 ns        42356 ns           10   74.8995k      18.0047      95.2638Mi/s
ascon_prf/1024/64_mean                      4697 ns         4694 ns           10   8.43314k      7.75105      221.037Mi/s
ascon_prf/1024/64_median                    4696 ns         4694 ns           10   8.43172k      7.74974      221.026Mi/s
ascon_prf/1024/64_stddev                    6.91 ns         4.60 ns           10    4.62962     4.25517m      221.543Ki/s
ascon_prf/1024/64_cv                        0.15 %          0.10 %            10      0.05%        0.05%            0.10%
ascon_prf/1024/64_min                       4690 ns         4689 ns           10   8.42755k      7.74591       220.64Mi/s
ascon_prf/1024/64_max                       4708 ns         4703 ns           10   8.43932k      7.75673      221.293Mi/s
ascon_hasha/256_mean                        3073 ns         3071 ns           10   5.51718k      19.1569      89.4297Mi/s
ascon_hasha/256_median                      3071 ns         3069 ns           10   5.51534k      19.1505       89.485Mi/s
ascon_hasha/256_stddev                      4.02 ns         3.38 ns           10    5.53898    0.0192326      100.828Ki/s
ascon_hasha/256_cv                          0.13 %          0.11 %            10      0.10%        0.10%            0.11%
ascon_hasha/256_min                         3069 ns         3068 ns           10   5.51526k      19.1502      89.2302Mi/s
ascon_hasha/256_max                         3078 ns         3078 ns           10   5.53294k      19.2116      89.5157Mi/s
ascon_permutation<1>_mean                   11.4 ns         11.4 ns           10    20.5236      0.51309      3.25824Gi/s
ascon_permutation<1>_median                 11.5 ns         11.4 ns           10    20.4985     0.512462      3.25613Gi/s
ascon_permutation<1>_stddev                0.052 ns        0.050 ns           10  0.0962438      2.4061m      14.5894Mi/s
ascon_permutation<1>_cv                     0.45 %          0.44 %            10      0.47%        0.47%            0.44%
ascon_permutation<1>_min                    11.4 ns         11.4 ns           10    20.4002     0.510005      3.23837Gi/s
ascon_permutation<1>_max                    11.5 ns         11.5 ns           10    20.6731     0.516827      3.28183Gi/s
ascon_hash/64_mean                          1616 ns         1615 ns           10    2.9025k      30.2344      56.6802Mi/s
ascon_hash/64_median                        1616 ns         1616 ns           10   2.90251k      30.2345      56.6651Mi/s
ascon_hash/64_stddev                        1.66 ns         1.35 ns           10    2.38657    0.0248601      48.4828Ki/s
ascon_hash/64_cv                            0.10 %          0.08 %            10      0.08%        0.08%            0.08%
ascon_hash/64_min                           1613 ns         1613 ns           10   2.89958k      30.2039      56.6118Mi/s
ascon_hash/64_max                           1618 ns         1617 ns           10    2.9057k      30.2677      56.7592Mi/s
ascon_prf/256/64_mean                       1797 ns         1796 ns           10   3.22488k      10.0777      169.939Mi/s
ascon_prf/256/64_median                     1798 ns         1796 ns           10   3.22449k      10.0765      169.952Mi/s
ascon_prf/256/64_stddev                     2.90 ns         2.15 ns           10    2.44161     7.63004m      208.311Ki/s
ascon_prf/256/64_cv                         0.16 %          0.12 %            10      0.08%        0.08%            0.12%
ascon_prf/256/64_min                        1793 ns         1793 ns           10   3.22231k      10.0697      169.613Mi/s
ascon_prf/256/64_max                        1802 ns         1799 ns           10   3.22806k      10.0877      170.225Mi/s
ascon128_aead_encrypt/256/32_mean           2221 ns         2220 ns           10   3.98897k      13.8506       123.71Mi/s
ascon128_aead_encrypt/256/32_median         2223 ns         2222 ns           10   3.99422k      13.8688      123.592Mi/s
ascon128_aead_encrypt/256/32_stddev         7.79 ns         7.53 ns           10    13.3216    0.0462555      429.949Ki/s
ascon128_aead_encrypt/256/32_cv             0.35 %          0.34 %            10      0.33%        0.33%            0.34%
ascon128_aead_encrypt/256/32_min            2210 ns         2210 ns           10   3.97253k      13.7935      123.047Mi/s
ascon128_aead_encrypt/256/32_max            2233 ns         2232 ns           10   4.01167k      13.9294      124.278Mi/s
ascon128a_aead_decrypt/1024/32_mean         7109 ns         7105 ns           10   12.7644k      12.0875      141.736Mi/s
ascon128a_aead_decrypt/1024/32_median       7103 ns         7101 ns           10   12.7629k      12.0861      141.823Mi/s
ascon128a_aead_decrypt/1024/32_stddev       12.6 ns         8.41 ns           10    3.44679       3.264m      171.583Ki/s
ascon128a_aead_decrypt/1024/32_cv           0.18 %          0.12 %            10      0.03%        0.03%            0.12%
ascon128a_aead_decrypt/1024/32_min          7100 ns         7099 ns           10   12.7617k      12.0849      141.369Mi/s
ascon128a_aead_decrypt/1024/32_max          7134 ns         7124 ns           10   12.7731k      12.0958      141.855Mi/s
ascon128a_aead_encrypt/64/32_mean            950 ns          950 ns           10   1.70515k       17.762      96.4237Mi/s
ascon128a_aead_encrypt/64/32_median          946 ns          946 ns           10   1.69915k      17.6995      96.8222Mi/s
ascon128a_aead_encrypt/64/32_stddev         6.51 ns         6.09 ns           10    10.3819     0.108144      629.458Ki/s
ascon128a_aead_encrypt/64/32_cv             0.68 %          0.64 %            10      0.61%        0.61%            0.64%
ascon128a_aead_encrypt/64/32_min             945 ns          945 ns           10   1.69911k      17.6991      95.3486Mi/s
ascon128a_aead_encrypt/64/32_max             962 ns          960 ns           10   1.72483k      17.9669      96.8595Mi/s
ascon_prfs_verify/1_mean                     199 ns          199 ns           10    357.025      21.0014      81.5683Mi/s
ascon_prfs_verify/1_median                   199 ns          199 ns           10    357.024      21.0014      81.6103Mi/s
ascon_prfs_verify/1_stddev                 0.426 ns        0.265 ns           10   4.15554m     244.443u      111.289Ki/s
ascon_prfs_verify/1_cv                      0.21 %          0.13 %            10      0.00%        0.00%            0.13%
ascon_prfs_verify/1_min                      199 ns          199 ns           10     357.02      21.0012      81.2893Mi/s
ascon_prfs_verify/1_max                      200 ns          199 ns           10    357.034       21.002       81.631Mi/s
ascon128a_aead_encrypt/256/32_mean          2156 ns         2155 ns           10   3.87185k      13.4439       127.46Mi/s
ascon128a_aead_encrypt/256/32_median        2155 ns         2155 ns           10   3.87208k      13.4447       127.47Mi/s
ascon128a_aead_encrypt/256/32_stddev        2.20 ns         1.47 ns           10    1.26759     4.40135m      89.0565Ki/s
ascon128a_aead_encrypt/256/32_cv            0.10 %          0.07 %            10      0.03%        0.03%            0.07%
ascon128a_aead_encrypt/256/32_min           2153 ns         2153 ns           10   3.87028k      13.4385      127.277Mi/s
ascon128a_aead_encrypt/256/32_max           2161 ns         2158 ns           10   3.87337k      13.4492      127.568Mi/s
ascon_xofa/64/64_mean                       1534 ns         1533 ns           10   2.75321k      21.5094      79.6371Mi/s
ascon_xofa/64/64_median                     1532 ns         1532 ns           10   2.75316k      21.5091      79.6919Mi/s
ascon_xofa/64/64_stddev                     2.96 ns         1.97 ns           10  0.0841255      657.23u      104.428Ki/s
ascon_xofa/64/64_cv                         0.19 %          0.13 %            10      0.00%        0.00%            0.13%
ascon_xofa/64/64_min                        1532 ns         1532 ns           10   2.75313k      21.5088      79.3884Mi/s
ascon_xofa/64/64_max                        1541 ns         1538 ns           10    2.7534k      21.5109      79.7026Mi/s
ascon128_aead_decrypt/4096/32_mean         27543 ns        27526 ns           10    49.442k      11.9772       143.02Mi/s
ascon128_aead_decrypt/4096/32_median       27531 ns        27517 ns           10   49.3876k       11.964      143.065Mi/s
ascon128_aead_decrypt/4096/32_stddev        62.2 ns         51.4 ns           10    80.4886    0.0194982      273.194Ki/s
ascon128_aead_decrypt/4096/32_cv            0.23 %          0.19 %            10      0.16%        0.16%            0.19%
ascon128_aead_decrypt/4096/32_min          27478 ns        27474 ns           10   49.3813k      11.9625      142.668Mi/s
ascon128_aead_decrypt/4096/32_max          27640 ns        27594 ns           10   49.5832k      12.0114      143.291Mi/s
ascon_prf/64/64_mean                        1061 ns         1061 ns           10   1.90421k      14.8767      115.091Mi/s
ascon_prf/64/64_median                      1059 ns         1059 ns           10   1.90195k       14.859      115.314Mi/s
ascon_prf/64/64_stddev                      4.74 ns         4.50 ns           10    6.97071    0.0544587      498.729Ki/s
ascon_prf/64/64_cv                          0.45 %          0.42 %            10      0.37%        0.37%            0.42%
ascon_prf/64/64_min                         1056 ns         1055 ns           10   1.89706k      14.8208      114.335Mi/s
ascon_prf/64/64_max                         1068 ns         1068 ns           10   1.91666k      14.9739      115.657Mi/s
ascon80pq_aead_decrypt/256/32_mean          2351 ns         2350 ns           10   4.22187k      14.6593      116.878Mi/s
ascon80pq_aead_decrypt/256/32_median        2351 ns         2350 ns           10   4.22383k      14.6661      116.862Mi/s
ascon80pq_aead_decrypt/256/32_stddev        6.12 ns         5.60 ns           10    8.61586    0.0299162      285.305Ki/s
ascon80pq_aead_decrypt/256/32_cv            0.26 %          0.24 %            10      0.20%        0.20%            0.24%
ascon80pq_aead_decrypt/256/32_min           2341 ns         2341 ns           10   4.20671k      14.6066      116.524Mi/s
ascon80pq_aead_decrypt/256/32_max           2360 ns         2357 ns           10    4.2338k      14.7007      117.342Mi/s
ascon_prf/4096/64_mean                     16291 ns        16280 ns           10   29.2429k      7.02955      243.694Mi/s
ascon_prf/4096/64_median                   16282 ns        16276 ns           10   29.2472k      7.03057      243.751Mi/s
ascon_prf/4096/64_stddev                    21.4 ns         14.4 ns           10    13.4549     3.23434m      220.259Ki/s
ascon_prf/4096/64_cv                        0.13 %          0.09 %            10      0.05%        0.05%            0.09%
ascon_prf/4096/64_min                      16260 ns        16255 ns           10   29.2135k      7.02249      243.372Mi/s
ascon_prf/4096/64_max                      16324 ns        16301 ns           10   29.2574k      7.03304      244.065Mi/s
ascon_hash/256_mean                         4444 ns         4441 ns           10   7.96786k      27.6662      61.8508Mi/s
ascon_hash/256_median                       4440 ns         4436 ns           10   7.96481k      27.6556      61.9161Mi/s
ascon_hash/256_stddev                       18.0 ns         16.3 ns           10    4.81837    0.0167304      230.951Ki/s
ascon_hash/256_cv                           0.41 %          0.37 %            10      0.06%        0.06%            0.36%
ascon_hash/256_min                          4431 ns         4431 ns           10   7.96441k      27.6542      61.2208Mi/s
ascon_hash/256_max                          4494 ns         4486 ns           10   7.97778k      27.7006      61.9925Mi/s
ascon128_aead_decrypt/256/32_mean           2318 ns         2315 ns           10   4.15364k      14.4224      118.645Mi/s
ascon128_aead_decrypt/256/32_median         2314 ns         2312 ns           10   4.15371k      14.4226      118.773Mi/s
ascon128_aead_decrypt/256/32_stddev         10.1 ns         6.63 ns           10    4.19877    0.0145791      346.746Ki/s
ascon128_aead_decrypt/256/32_cv             0.44 %          0.29 %            10      0.10%        0.10%            0.29%
ascon128_aead_decrypt/256/32_min            2309 ns         2308 ns           10   4.14801k      14.4028      117.841Mi/s
ascon128_aead_decrypt/256/32_max            2343 ns         2331 ns           10   4.16071k      14.4469      118.985Mi/s
ascon_xof/4096/64_mean                     61434 ns        61387 ns           10   110.238k      26.4996      64.6273Mi/s
ascon_xof/4096/64_median                   61374 ns        61343 ns           10    110.24k         26.5      64.6733Mi/s
ascon_xof/4096/64_stddev                     124 ns         86.0 ns           10    10.5773     2.54262m      92.6043Ki/s
ascon_xof/4096/64_cv                        0.20 %          0.14 %            10      0.01%        0.01%            0.14%
ascon_xof/4096/64_min                      61333 ns        61326 ns           10   110.225k      26.4963      64.4471Mi/s
ascon_xof/4096/64_max                      61681 ns        61559 ns           10   110.254k      26.5034      64.6917Mi/s
ascon_prfs_verify/4_mean                     197 ns          197 ns           10    354.035      17.7017      96.7112Mi/s
ascon_prfs_verify/4_median                   197 ns          197 ns           10    354.028      17.7014      96.7668Mi/s
ascon_prfs_verify/4_stddev                 0.561 ns        0.363 ns           10  0.0197326     986.632u      181.746Ki/s
ascon_prfs_verify/4_cv                      0.28 %          0.18 %            10      0.01%        0.01%            0.18%
ascon_prfs_verify/4_min                      197 ns          197 ns           10    354.019       17.701      96.2589Mi/s
ascon_prfs_verify/4_max                      199 ns          198 ns           10    354.077      17.7039      96.8489Mi/s
ascon_prfs_authenticate/4_mean               160 ns          160 ns           10    287.028      14.3514      119.378Mi/s
ascon_prfs_authenticate/4_median             160 ns          160 ns           10    287.016      14.3508      119.432Mi/s
ascon_prfs_authenticate/4_stddev           0.258 ns        0.157 ns           10  0.0394284     1.97142m      120.056Ki/s
ascon_prfs_authenticate/4_cv                0.16 %          0.10 %            10      0.01%        0.01%            0.10%
ascon_prfs_authenticate/4_min                160 ns          160 ns           10    287.013      14.3507      119.155Mi/s
ascon_prfs_authenticate/4_max                160 ns          160 ns           10     287.14       14.357      119.457Mi/s
ascon_mac_verify/64_mean                     703 ns          702 ns           10   1.26225k      13.1484      130.347Mi/s
ascon_mac_verify/64_median                   702 ns          702 ns           10   1.26224k      13.1483      130.349Mi/s
ascon_mac_verify/64_stddev                 0.721 ns        0.579 ns           10   0.815607      8.4959m      110.039Ki/s
ascon_mac_verify/64_cv                      0.10 %          0.08 %            10      0.06%        0.06%            0.08%
ascon_mac_verify/64_min                      702 ns          702 ns           10   1.26116k       13.137      130.177Mi/s
ascon_mac_verify/64_max                      704 ns          703 ns           10   1.26389k      13.1655      130.478Mi/s
ascon_hasha/4096_mean                      41339 ns        41308 ns           10    74.203k      17.9755      95.3019Mi/s
ascon_hasha/4096_median                    41335 ns        41300 ns           10   74.2038k      17.9757      95.3209Mi/s
ascon_hasha/4096_stddev                     45.3 ns         29.3 ns           10    9.44499     2.28803m      69.2378Ki/s
ascon_hasha/4096_cv                         0.11 %          0.07 %            10      0.01%        0.01%            0.07%
ascon_hasha/4096_min                       41289 ns        41277 ns           10   74.1892k      17.9722      95.1827Mi/s
ascon_hasha/4096_max                       41416 ns        41360 ns           10   74.2189k      17.9794      95.3742Mi/s
ascon128_aead_encrypt/1024/32_mean          7152 ns         7148 ns           10   12.8296k      12.1492      140.888Mi/s
ascon128_aead_encrypt/1024/32_median        7142 ns         7139 ns           10   12.8305k      12.1501      141.061Mi/s
ascon128_aead_encrypt/1024/32_stddev        30.7 ns         26.8 ns           10    1.91657     1.81493m      536.243Ki/s
ascon128_aead_encrypt/1024/32_cv            0.43 %          0.38 %            10      0.01%        0.01%            0.37%
ascon128_aead_encrypt/1024/32_min           7137 ns         7136 ns           10   12.8272k       12.147      139.408Mi/s
ascon128_aead_encrypt/1024/32_max           7238 ns         7224 ns           10   12.8325k       12.152      141.126Mi/s
ascon_permutation<6>_mean                   52.4 ns         52.4 ns           10    94.0049      2.35012      728.615Mi/s
ascon_permutation<6>_median                 52.3 ns         52.3 ns           10    94.0035      2.35009      729.256Mi/s
ascon_permutation<6>_stddev                0.149 ns        0.093 ns           10   2.98522m     74.6306u      1.29109Mi/s
ascon_permutation<6>_cv                     0.28 %          0.18 %            10      0.00%        0.00%            0.18%
ascon_permutation<6>_min                    52.3 ns         52.3 ns           10    94.0024      2.35006      725.276Mi/s
ascon_permutation<6>_max                    52.8 ns         52.6 ns           10    94.0119       2.3503       729.49Mi/s
ascon128a_aead_decrypt/64/32_mean            996 ns          996 ns           10    1.7879k      18.6239      91.9671Mi/s
ascon128a_aead_decrypt/64/32_median          995 ns          994 ns           10   1.78637k       18.608       92.076Mi/s
ascon128a_aead_decrypt/64/32_stddev         3.21 ns         3.14 ns           10    5.81908    0.0606155      295.395Ki/s
ascon128a_aead_decrypt/64/32_cv             0.32 %          0.32 %            10      0.33%        0.33%            0.31%
ascon128a_aead_decrypt/64/32_min             994 ns          993 ns           10   1.78355k      18.5787      91.1987Mi/s
ascon128a_aead_decrypt/64/32_max            1004 ns         1004 ns           10   1.80419k      18.7936      92.1632Mi/s
ascon_mac_verify/4096_mean                 17358 ns        17345 ns           10    31.157k      7.54773      226.965Mi/s
ascon_mac_verify/4096_median               17354 ns        17344 ns           10   31.1451k      7.54484      226.978Mi/s
ascon_mac_verify/4096_stddev                33.4 ns         28.8 ns           10    48.6116    0.0117761      385.138Ki/s
ascon_mac_verify/4096_cv                    0.19 %          0.17 %            10      0.16%        0.16%            0.17%
ascon_mac_verify/4096_min                  17313 ns        17305 ns           10   31.1023k      7.53447      226.309Mi/s
ascon_mac_verify/4096_max                  17398 ns        17396 ns           10   31.2654k      7.57398      227.496Mi/s
ascon_mac_authenticate/64_mean               663 ns          663 ns           10    1.1908k       14.885      115.073Mi/s
ascon_mac_authenticate/64_median             663 ns          662 ns           10      1.19k       14.875      115.166Mi/s
ascon_mac_authenticate/64_stddev            1.76 ns         1.68 ns           10    3.03662    0.0379577      299.047Ki/s
ascon_mac_authenticate/64_cv                0.26 %          0.25 %            10      0.26%        0.26%            0.25%
ascon_mac_authenticate/64_min                661 ns          661 ns           10   1.18816k       14.852      114.582Mi/s
ascon_mac_authenticate/64_max                666 ns          666 ns           10   1.19688k       14.961      115.408Mi/s
ascon80pq_aead_encrypt/256/32_mean          2256 ns         2254 ns           10   4.04817k      14.0562      121.838Mi/s
ascon80pq_aead_encrypt/256/32_median        2255 ns         2254 ns           10   4.04948k      14.0607      121.835Mi/s
ascon80pq_aead_encrypt/256/32_stddev        12.8 ns         10.4 ns           10     11.616    0.0403334      571.214Ki/s
ascon80pq_aead_encrypt/256/32_cv            0.57 %          0.46 %            10      0.29%        0.29%            0.46%
ascon80pq_aead_encrypt/256/32_min           2241 ns         2241 ns           10   4.02741k      13.9841      120.547Mi/s
ascon80pq_aead_encrypt/256/32_max           2287 ns         2278 ns           10   4.06416k      14.1117      122.577Mi/s
ascon128a_aead_encrypt/1024/32_mean         6938 ns         6936 ns           10    12.465k      11.8039      145.197Mi/s
ascon128a_aead_encrypt/1024/32_median       6937 ns         6936 ns           10   12.4652k      11.8041      145.206Mi/s
ascon128a_aead_encrypt/1024/32_stddev       4.61 ns         2.41 ns           10    1.12986     1.06995m      51.7133Ki/s
ascon128a_aead_encrypt/1024/32_cv           0.07 %          0.03 %            10      0.01%        0.01%            0.03%
ascon128a_aead_encrypt/1024/32_min          6934 ns         6934 ns           10   12.4633k      11.8024      145.065Mi/s
ascon128a_aead_encrypt/1024/32_max          6950 ns         6942 ns           10   12.4665k      11.8054      145.246Mi/s
ascon_xof/64/64_mean                        2139 ns         2138 ns           10   3.84123k      30.0096      57.1032Mi/s
ascon_xof/64/64_median                      2138 ns         2137 ns           10   3.84121k      30.0094      57.1155Mi/s
ascon_xof/64/64_stddev                      1.89 ns         1.19 ns           10  0.0455312     355.713u       32.468Ki/s
ascon_xof/64/64_cv                          0.09 %          0.06 %            10      0.00%        0.00%            0.06%
ascon_xof/64/64_min                         2137 ns         2137 ns           10   3.84117k      30.0091      57.0226Mi/s
ascon_xof/64/64_max                         2143 ns         2141 ns           10   3.84133k      30.0104      57.1276Mi/s
ascon80pq_aead_decrypt/64/32_mean           1052 ns         1051 ns           10   1.88749k      19.6614      87.0759Mi/s
ascon80pq_aead_decrypt/64/32_median         1052 ns         1051 ns           10   1.88751k      19.6616      87.0848Mi/s
ascon80pq_aead_decrypt/64/32_stddev         1.79 ns         1.20 ns           10    2.06251    0.0214845      101.411Ki/s
ascon80pq_aead_decrypt/64/32_cv             0.17 %          0.11 %            10      0.11%        0.11%            0.11%
ascon80pq_aead_decrypt/64/32_min            1049 ns         1049 ns           10   1.88529k      19.6385      86.9185Mi/s
ascon80pq_aead_decrypt/64/32_max            1056 ns         1053 ns           10    1.8898k      19.6854      87.2789Mi/s
ascon_mac_authenticate/4096_mean           17338 ns        17328 ns           10   31.1246k       7.5692      226.311Mi/s
ascon_mac_authenticate/4096_median         17337 ns        17332 ns           10   31.1125k      7.56627      226.264Mi/s
ascon_mac_authenticate/4096_stddev          38.8 ns         36.0 ns           10    68.3174    0.0166142      481.007Ki/s
ascon_mac_authenticate/4096_cv              0.22 %          0.21 %            10      0.22%        0.22%            0.21%
ascon_mac_authenticate/4096_min            17285 ns        17284 ns           10    31.045k      7.54986      225.382Mi/s
ascon_mac_authenticate/4096_max            17402 ns        17399 ns           10   31.2734k      7.60539      226.887Mi/s
ascon_permutation<8>_mean                   81.2 ns         81.1 ns           10    145.589      3.63973       470.31Mi/s
ascon_permutation<8>_median                 81.1 ns         81.0 ns           10     145.63      3.64075      470.747Mi/s
ascon_permutation<8>_stddev                0.438 ns        0.404 ns           10   0.373235     9.33087m      2.32738Mi/s
ascon_permutation<8>_cv                     0.54 %          0.50 %            10      0.26%        0.26%            0.49%
ascon_permutation<8>_min                    80.6 ns         80.6 ns           10    144.884      3.62209      464.846Mi/s
ascon_permutation<8>_max                    82.2 ns         82.1 ns           10    146.019      3.65048      473.221Mi/s
ascon_xof/1024/64_mean                     16278 ns        16264 ns           10   29.1978k      26.8362      63.7961Mi/s
ascon_xof/1024/64_median                   16252 ns        16247 ns           10   29.1963k      26.8349      63.8634Mi/s
ascon_xof/1024/64_stddev                    51.2 ns         33.6 ns           10    3.77446     3.46918m      134.727Ki/s
ascon_xof/1024/64_cv                        0.31 %          0.21 %            10      0.01%        0.01%            0.21%
ascon_xof/1024/64_min                      16243 ns        16241 ns           10   29.1949k      26.8336      63.4927Mi/s
ascon_xof/1024/64_max                      16398 ns        16342 ns           10   29.2068k      26.8445      63.8879Mi/s
ascon_xof/256/64_mean                       4962 ns         4959 ns           10   8.90584k      27.8308      61.5424Mi/s
ascon_xof/256/64_median                     4958 ns         4956 ns           10   8.90554k      27.8298      61.5807Mi/s
ascon_xof/256/64_stddev                     7.60 ns         5.30 ns           10   0.719311     2.24785m      67.3358Ki/s
ascon_xof/256/64_cv                         0.15 %          0.11 %            10      0.01%        0.01%            0.11%
ascon_xof/256/64_min                        4955 ns         4954 ns           10   8.90548k      27.8296      61.4113Mi/s
ascon_xof/256/64_max                        4975 ns         4969 ns           10   8.90776k      27.8367      61.6039Mi/s
```

### On Apple M1 Max

Compiled with **Apple clang version 15.0.0 (clang-1500.1.0.2.5)**.

```bash
$ uname -srm
Darwin 23.3.0 arm64
```

```bash
2024-02-04T15:22:49+04:00
Running ./build/benchmarks/bench.out
Run on (10 X 24 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB
  L1 Instruction 128 KiB
  L2 Unified 4096 KiB (x10)
Load Average: 3.49, 5.55, 6.24
-------------------------------------------------------------------------------------------------
Benchmark                                      Time             CPU   Iterations bytes_per_second
-------------------------------------------------------------------------------------------------
ascon128a_aead_encrypt/4096/32_mean         8141 ns         8099 ns           10      486.052Mi/s
ascon128a_aead_encrypt/4096/32_median       8138 ns         8094 ns           10      486.354Mi/s
ascon128a_aead_encrypt/4096/32_stddev       16.1 ns         11.0 ns           10      673.042Ki/s
ascon128a_aead_encrypt/4096/32_cv           0.20 %          0.14 %            10            0.14%
ascon128a_aead_encrypt/4096/32_min          8120 ns         8092 ns           10      484.331Mi/s
ascon128a_aead_encrypt/4096/32_max          8181 ns         8128 ns           10      486.479Mi/s
ascon_prfs_authenticate/16_mean             51.7 ns         51.5 ns           10      592.422Mi/s
ascon_prfs_authenticate/16_median           51.6 ns         51.4 ns           10      593.884Mi/s
ascon_prfs_authenticate/16_stddev          0.282 ns        0.321 ns           10      3.64703Mi/s
ascon_prfs_authenticate/16_cv               0.54 %          0.62 %            10            0.62%
ascon_prfs_authenticate/16_min              51.5 ns         51.3 ns           10      582.783Mi/s
ascon_prfs_authenticate/16_max              52.5 ns         52.4 ns           10      594.848Mi/s
ascon_prf/1024/64_mean                      1787 ns         1776 ns           10      584.117Mi/s
ascon_prf/1024/64_median                    1785 ns         1776 ns           10      584.224Mi/s
ascon_prf/1024/64_stddev                    9.59 ns        0.569 ns           10      191.393Ki/s
ascon_prf/1024/64_cv                        0.54 %          0.03 %            10            0.03%
ascon_prf/1024/64_min                       1779 ns         1776 ns           10      583.809Mi/s
ascon_prf/1024/64_max                       1814 ns         1777 ns           10      584.272Mi/s
ascon_hash/4096_mean                       23580 ns        23466 ns           10      167.765Mi/s
ascon_hash/4096_median                     23576 ns        23460 ns           10      167.809Mi/s
ascon_hash/4096_stddev                      27.7 ns         22.7 ns           10       165.78Ki/s
ascon_hash/4096_cv                          0.12 %          0.10 %            10            0.10%
ascon_hash/4096_min                        23547 ns        23440 ns           10      167.421Mi/s
ascon_hash/4096_max                        23650 ns        23514 ns           10      167.953Mi/s
ascon_hasha/1024_mean                       4082 ns         4064 ns           10      247.831Mi/s
ascon_hasha/1024_median                     4082 ns         4063 ns           10       247.88Mi/s
ascon_hasha/1024_stddev                     3.87 ns         4.11 ns           10      256.226Ki/s
ascon_hasha/1024_cv                         0.09 %          0.10 %            10            0.10%
ascon_hasha/1024_min                        4074 ns         4060 ns           10      247.262Mi/s
ascon_hasha/1024_max                        4087 ns         4073 ns           10      248.055Mi/s
ascon_xof/4096/64_mean                     23747 ns        23640 ns           10      167.822Mi/s
ascon_xof/4096/64_median                   23750 ns        23635 ns           10      167.856Mi/s
ascon_xof/4096/64_stddev                    19.2 ns         16.6 ns           10      120.904Ki/s
ascon_xof/4096/64_cv                        0.08 %          0.07 %            10            0.07%
ascon_xof/4096/64_min                      23709 ns        23625 ns           10      167.602Mi/s
ascon_xof/4096/64_max                      23772 ns        23671 ns           10      167.925Mi/s
ascon_prfs_verify/16_mean                   51.7 ns         51.5 ns           10        593.1Mi/s
ascon_prfs_verify/16_median                 51.7 ns         51.4 ns           10      593.314Mi/s
ascon_prfs_verify/16_stddev                0.128 ns        0.064 ns           10       758.98Ki/s
ascon_prfs_verify/16_cv                     0.25 %          0.13 %            10            0.12%
ascon_prfs_verify/16_min                    51.4 ns         51.4 ns           10       591.12Mi/s
ascon_prfs_verify/16_max                    51.9 ns         51.6 ns           10      593.897Mi/s
ascon_mac_verify/256_mean                    523 ns          521 ns           10      527.587Mi/s
ascon_mac_verify/256_median                  523 ns          520 ns           10      527.776Mi/s
ascon_mac_verify/256_stddev                0.979 ns        0.504 ns           10      522.179Ki/s
ascon_mac_verify/256_cv                     0.19 %          0.10 %            10            0.10%
ascon_mac_verify/256_min                     521 ns          520 ns           10      526.485Mi/s
ascon_mac_verify/256_max                     525 ns          522 ns           10      528.274Mi/s
ascon128_aead_encrypt/64/32_mean             397 ns          395 ns           10      231.891Mi/s
ascon128_aead_encrypt/64/32_median           397 ns          395 ns           10      231.795Mi/s
ascon128_aead_encrypt/64/32_stddev         0.879 ns        0.845 ns           10      508.513Ki/s
ascon128_aead_encrypt/64/32_cv              0.22 %          0.21 %            10            0.21%
ascon128_aead_encrypt/64/32_min              395 ns          394 ns           10      231.277Mi/s
ascon128_aead_encrypt/64/32_max              398 ns          396 ns           10      232.656Mi/s
ascon_permutation<8>_mean                   31.6 ns         31.5 ns           10      1.18253Gi/s
ascon_permutation<8>_median                 31.6 ns         31.5 ns           10      1.18265Gi/s
ascon_permutation<8>_stddev                0.036 ns        0.026 ns           10      1019.52Ki/s
ascon_permutation<8>_cv                     0.11 %          0.08 %            10            0.08%
ascon_permutation<8>_min                    31.6 ns         31.5 ns           10      1.18028Gi/s
ascon_permutation<8>_max                    31.7 ns         31.6 ns           10      1.18344Gi/s
ascon_permutation<1>_mean                   5.83 ns         5.80 ns           10      6.42248Gi/s
ascon_permutation<1>_median                 5.83 ns         5.80 ns           10      6.42394Gi/s
ascon_permutation<1>_stddev                0.005 ns        0.003 ns           10      3.41816Mi/s
ascon_permutation<1>_cv                     0.09 %          0.05 %            10            0.05%
ascon_permutation<1>_min                    5.82 ns         5.80 ns           10      6.41538Gi/s
ascon_permutation<1>_max                    5.84 ns         5.81 ns           10      6.42528Gi/s
ascon80pq_aead_encrypt/4096/32_mean        11860 ns        11808 ns           10      333.397Mi/s
ascon80pq_aead_encrypt/4096/32_median      11860 ns        11800 ns           10      333.617Mi/s
ascon80pq_aead_encrypt/4096/32_stddev       30.6 ns         24.3 ns           10      700.774Ki/s
ascon80pq_aead_encrypt/4096/32_cv           0.26 %          0.21 %            10            0.21%
ascon80pq_aead_encrypt/4096/32_min         11810 ns        11794 ns           10      331.536Mi/s
ascon80pq_aead_encrypt/4096/32_max         11925 ns        11874 ns           10      333.799Mi/s
ascon_xof/1024/64_mean                      6270 ns         6239 ns           10      166.296Mi/s
ascon_xof/1024/64_median                    6271 ns         6238 ns           10      166.336Mi/s
ascon_xof/1024/64_stddev                    2.31 ns         2.24 ns           10      61.2483Ki/s
ascon_xof/1024/64_cv                        0.04 %          0.04 %            10            0.04%
ascon_xof/1024/64_min                       6266 ns         6237 ns           10      166.208Mi/s
ascon_xof/1024/64_max                       6273 ns         6243 ns           10      166.349Mi/s
ascon128a_aead_decrypt/64/32_mean            325 ns          324 ns           10      282.892Mi/s
ascon128a_aead_decrypt/64/32_median          325 ns          324 ns           10      282.965Mi/s
ascon128a_aead_decrypt/64/32_stddev        0.322 ns        0.224 ns           10      200.262Ki/s
ascon128a_aead_decrypt/64/32_cv             0.10 %          0.07 %            10            0.07%
ascon128a_aead_decrypt/64/32_min             325 ns          323 ns           10      282.462Mi/s
ascon128a_aead_decrypt/64/32_max             326 ns          324 ns           10      283.122Mi/s
ascon_mac_authenticate/64_mean               240 ns          239 ns           10      318.923Mi/s
ascon_mac_authenticate/64_median             240 ns          239 ns           10      319.422Mi/s
ascon_mac_authenticate/64_stddev           0.777 ns        0.767 ns           10      1.02022Mi/s
ascon_mac_authenticate/64_cv                0.32 %          0.32 %            10            0.32%
ascon_mac_authenticate/64_min                240 ns          239 ns           10      317.127Mi/s
ascon_mac_authenticate/64_max                242 ns          241 ns           10      319.875Mi/s
ascon_mac_authenticate/1024_mean            1651 ns         1643 ns           10      603.602Mi/s
ascon_mac_authenticate/1024_median          1651 ns         1643 ns           10      603.619Mi/s
ascon_mac_authenticate/1024_stddev         0.751 ns        0.951 ns           10      357.748Ki/s
ascon_mac_authenticate/1024_cv              0.05 %          0.06 %            10            0.06%
ascon_mac_authenticate/1024_min             1650 ns         1642 ns           10      602.991Mi/s
ascon_mac_authenticate/1024_max             1652 ns         1645 ns           10      604.038Mi/s
ascon80pq_aead_encrypt/1024/32_mean         3125 ns         3111 ns           10      323.752Mi/s
ascon80pq_aead_encrypt/1024/32_median       3123 ns         3109 ns           10      323.931Mi/s
ascon80pq_aead_encrypt/1024/32_stddev       7.81 ns         6.15 ns           10      653.346Ki/s
ascon80pq_aead_encrypt/1024/32_cv           0.25 %          0.20 %            10            0.20%
ascon80pq_aead_encrypt/1024/32_min          3118 ns         3106 ns           10      322.075Mi/s
ascon80pq_aead_encrypt/1024/32_max          3146 ns         3127 ns           10      324.249Mi/s
ascon_prfs_verify/1_mean                    54.2 ns         53.9 ns           10      300.748Mi/s
ascon_prfs_verify/1_median                  54.4 ns         54.1 ns           10      299.593Mi/s
ascon_prfs_verify/1_stddev                 0.415 ns        0.398 ns           10      2.22831Mi/s
ascon_prfs_verify/1_cv                      0.77 %          0.74 %            10            0.74%
ascon_prfs_verify/1_min                     53.7 ns         53.4 ns           10      298.265Mi/s
ascon_prfs_verify/1_max                     54.6 ns         54.4 ns           10      303.615Mi/s
ascon128a_aead_encrypt/1024/32_mean         2174 ns         2164 ns           10      465.402Mi/s
ascon128a_aead_encrypt/1024/32_median       2174 ns         2163 ns           10      465.496Mi/s
ascon128a_aead_encrypt/1024/32_stddev       3.17 ns         1.31 ns           10      287.458Ki/s
ascon128a_aead_encrypt/1024/32_cv           0.15 %          0.06 %            10            0.06%
ascon128a_aead_encrypt/1024/32_min          2167 ns         2163 ns           10      464.672Mi/s
ascon128a_aead_encrypt/1024/32_max          2180 ns         2167 ns           10      465.694Mi/s
ascon80pq_aead_encrypt/256/32_mean           940 ns          936 ns           10      293.532Mi/s
ascon80pq_aead_encrypt/256/32_median         940 ns          936 ns           10      293.579Mi/s
ascon80pq_aead_encrypt/256/32_stddev       0.504 ns        0.373 ns           10      119.768Ki/s
ascon80pq_aead_encrypt/256/32_cv            0.05 %          0.04 %            10            0.04%
ascon80pq_aead_encrypt/256/32_min            940 ns          935 ns           10      293.339Mi/s
ascon80pq_aead_encrypt/256/32_max            941 ns          936 ns           10      293.712Mi/s
ascon_xof/64/64_mean                         793 ns          789 ns           10      154.783Mi/s
ascon_xof/64/64_median                       793 ns          789 ns           10      154.762Mi/s
ascon_xof/64/64_stddev                     0.474 ns        0.307 ns           10      61.7382Ki/s
ascon_xof/64/64_cv                          0.06 %          0.04 %            10            0.04%
ascon_xof/64/64_min                          792 ns          788 ns           10      154.713Mi/s
ascon_xof/64/64_max                          793 ns          789 ns           10      154.858Mi/s
ascon128a_aead_encrypt/64/32_mean            314 ns          312 ns           10      293.091Mi/s
ascon128a_aead_encrypt/64/32_median          314 ns          312 ns           10      293.202Mi/s
ascon128a_aead_encrypt/64/32_stddev        0.634 ns        0.619 ns           10      594.353Ki/s
ascon128a_aead_encrypt/64/32_cv             0.20 %          0.20 %            10            0.20%
ascon128a_aead_encrypt/64/32_min             313 ns          312 ns           10      292.149Mi/s
ascon128a_aead_encrypt/64/32_max             315 ns          313 ns           10       293.71Mi/s
ascon128_aead_decrypt/4096/32_mean         11900 ns        11849 ns           10      332.233Mi/s
ascon128_aead_decrypt/4096/32_median       11905 ns        11851 ns           10       332.18Mi/s
ascon128_aead_decrypt/4096/32_stddev        15.6 ns         5.13 ns           10      147.309Ki/s
ascon128_aead_decrypt/4096/32_cv            0.13 %          0.04 %            10            0.04%
ascon128_aead_decrypt/4096/32_min          11872 ns        11842 ns           10      332.048Mi/s
ascon128_aead_decrypt/4096/32_max          11924 ns        11856 ns           10      332.445Mi/s
ascon_hasha/256_mean                        1168 ns         1162 ns           10      236.413Mi/s
ascon_hasha/256_median                      1166 ns         1160 ns           10       236.73Mi/s
ascon_hasha/256_stddev                      8.10 ns         4.27 ns           10      882.641Ki/s
ascon_hasha/256_cv                          0.69 %          0.37 %            10            0.36%
ascon_hasha/256_min                         1164 ns         1160 ns           10      234.039Mi/s
ascon_hasha/256_max                         1191 ns         1174 ns           10      236.864Mi/s
ascon128_aead_encrypt/256/32_mean            942 ns          939 ns           10      292.509Mi/s
ascon128_aead_encrypt/256/32_median          943 ns          938 ns           10      292.663Mi/s
ascon128_aead_encrypt/256/32_stddev         1.59 ns         1.47 ns           10      467.954Ki/s
ascon128_aead_encrypt/256/32_cv             0.17 %          0.16 %            10            0.16%
ascon128_aead_encrypt/256/32_min             939 ns          938 ns           10      291.364Mi/s
ascon128_aead_encrypt/256/32_max             945 ns          943 ns           10      292.903Mi/s
ascon80pq_aead_decrypt/64/32_mean            404 ns          402 ns           10       227.82Mi/s
ascon80pq_aead_decrypt/64/32_median          404 ns          402 ns           10      227.801Mi/s
ascon80pq_aead_decrypt/64/32_stddev        0.458 ns        0.394 ns           10      228.652Ki/s
ascon80pq_aead_decrypt/64/32_cv             0.11 %          0.10 %            10            0.10%
ascon80pq_aead_decrypt/64/32_min             403 ns          401 ns           10      227.506Mi/s
ascon80pq_aead_decrypt/64/32_max             404 ns          402 ns           10      228.217Mi/s
ascon_prf/256/64_mean                        656 ns          653 ns           10      467.031Mi/s
ascon_prf/256/64_median                      657 ns          653 ns           10      467.051Mi/s
ascon_prf/256/64_stddev                    0.462 ns        0.369 ns           10      269.963Ki/s
ascon_prf/256/64_cv                         0.07 %          0.06 %            10            0.06%
ascon_prf/256/64_min                         656 ns          653 ns           10      466.455Mi/s
ascon_prf/256/64_max                         657 ns          654 ns           10      467.409Mi/s
ascon128_aead_decrypt/256/32_mean            955 ns          950 ns           10      289.109Mi/s
ascon128_aead_decrypt/256/32_median          954 ns          950 ns           10      289.193Mi/s
ascon128_aead_decrypt/256/32_stddev         1.70 ns         1.12 ns           10      348.329Ki/s
ascon128_aead_decrypt/256/32_cv             0.18 %          0.12 %            10            0.12%
ascon128_aead_decrypt/256/32_min             953 ns          949 ns           10      288.197Mi/s
ascon128_aead_decrypt/256/32_max             959 ns          953 ns           10      289.391Mi/s
ascon_permutation<12>_mean                  46.8 ns         46.6 ns           10      819.122Mi/s
ascon_permutation<12>_median                46.8 ns         46.5 ns           10      819.527Mi/s
ascon_permutation<12>_stddev               0.087 ns        0.064 ns           10      1.12844Mi/s
ascon_permutation<12>_cv                    0.19 %          0.14 %            10            0.14%
ascon_permutation<12>_min                   46.7 ns         46.5 ns           10      817.025Mi/s
ascon_permutation<12>_max                   47.0 ns         46.7 ns           10      820.124Mi/s
ascon128_aead_encrypt/4096/32_mean         11902 ns        11845 ns           10      332.366Mi/s
ascon128_aead_encrypt/4096/32_median       11897 ns        11839 ns           10      332.534Mi/s
ascon128_aead_encrypt/4096/32_stddev        10.1 ns         10.5 ns           10      300.843Ki/s
ascon128_aead_encrypt/4096/32_cv            0.08 %          0.09 %            10            0.09%
ascon128_aead_encrypt/4096/32_min          11891 ns        11836 ns           10      331.706Mi/s
ascon128_aead_encrypt/4096/32_max          11919 ns        11868 ns           10      332.602Mi/s
ascon128_aead_decrypt/1024/32_mean          3141 ns         3125 ns           10      322.218Mi/s
ascon128_aead_decrypt/1024/32_median        3141 ns         3125 ns           10      322.275Mi/s
ascon128_aead_decrypt/1024/32_stddev        1.37 ns         1.11 ns           10      117.546Ki/s
ascon128_aead_decrypt/1024/32_cv            0.04 %          0.04 %            10            0.04%
ascon128_aead_decrypt/1024/32_min           3140 ns         3124 ns           10       322.02Mi/s
ascon128_aead_decrypt/1024/32_max           3144 ns         3127 ns           10      322.322Mi/s
ascon80pq_aead_decrypt/256/32_mean           956 ns          951 ns           10      288.774Mi/s
ascon80pq_aead_decrypt/256/32_median         955 ns          950 ns           10      289.171Mi/s
ascon80pq_aead_decrypt/256/32_stddev        4.51 ns         4.22 ns           10       1.2665Mi/s
ascon80pq_aead_decrypt/256/32_cv            0.47 %          0.44 %            10            0.44%
ascon80pq_aead_decrypt/256/32_min            953 ns          949 ns           10      285.232Mi/s
ascon80pq_aead_decrypt/256/32_max            968 ns          963 ns           10      289.483Mi/s
ascon_mac_verify/1024_mean                  1651 ns         1643 ns           10       613.09Mi/s
ascon_mac_verify/1024_median                1651 ns         1643 ns           10      613.001Mi/s
ascon_mac_verify/1024_stddev               0.757 ns        0.665 ns           10      254.254Ki/s
ascon_mac_verify/1024_cv                    0.05 %          0.04 %            10            0.04%
ascon_mac_verify/1024_min                   1649 ns         1642 ns           10      612.793Mi/s
ascon_mac_verify/1024_max                   1652 ns         1643 ns           10      613.472Mi/s
ascon80pq_aead_decrypt/4096/32_mean        11922 ns        11864 ns           10      331.825Mi/s
ascon80pq_aead_decrypt/4096/32_median      11913 ns        11848 ns           10      332.274Mi/s
ascon80pq_aead_decrypt/4096/32_stddev       37.5 ns         35.6 ns           10      1014.44Ki/s
ascon80pq_aead_decrypt/4096/32_cv           0.31 %          0.30 %            10            0.30%
ascon80pq_aead_decrypt/4096/32_min         11889 ns        11839 ns           10      329.992Mi/s
ascon80pq_aead_decrypt/4096/32_max         12009 ns        11930 ns           10      332.533Mi/s
ascon_xofa/256/64_mean                      1293 ns         1287 ns           10      237.069Mi/s
ascon_xofa/256/64_median                    1293 ns         1286 ns           10      237.244Mi/s
ascon_xofa/256/64_stddev                    3.28 ns         2.06 ns           10      387.094Ki/s
ascon_xofa/256/64_cv                        0.25 %          0.16 %            10            0.16%
ascon_xofa/256/64_min                       1287 ns         1286 ns           10      236.059Mi/s
ascon_xofa/256/64_max                       1300 ns         1293 ns           10      237.273Mi/s
ascon_prf/4096/64_mean                      6304 ns         6276 ns           10      632.173Mi/s
ascon_prf/4096/64_median                    6302 ns         6272 ns           10      632.539Mi/s
ascon_prf/4096/64_stddev                    10.4 ns         12.2 ns           10      1.21871Mi/s
ascon_prf/4096/64_cv                        0.16 %          0.19 %            10            0.19%
ascon_prf/4096/64_min                       6295 ns         6268 ns           10      628.773Mi/s
ascon_prf/4096/64_max                       6332 ns         6310 ns           10      632.908Mi/s
ascon_hash/1024_mean                        6091 ns         6062 ns           10      166.121Mi/s
ascon_hash/1024_median                      6086 ns         6055 ns           10      166.313Mi/s
ascon_hash/1024_stddev                      25.9 ns         24.1 ns           10      669.078Ki/s
ascon_hash/1024_cv                          0.43 %          0.40 %            10            0.39%
ascon_hash/1024_min                         6064 ns         6051 ns           10       164.27Mi/s
ascon_hash/1024_max                         6161 ns         6131 ns           10      166.431Mi/s
ascon_prf/64/64_mean                         375 ns          374 ns           10      326.778Mi/s
ascon_prf/64/64_median                       375 ns          374 ns           10      326.741Mi/s
ascon_prf/64/64_stddev                     0.367 ns        0.203 ns           10      182.215Ki/s
ascon_prf/64/64_cv                          0.10 %          0.05 %            10            0.05%
ascon_prf/64/64_min                          374 ns          373 ns           10      326.408Mi/s
ascon_prf/64/64_max                          376 ns          374 ns           10      326.968Mi/s
ascon_xof/256/64_mean                       1902 ns         1892 ns           10      161.303Mi/s
ascon_xof/256/64_median                     1901 ns         1892 ns           10      161.318Mi/s
ascon_xof/256/64_stddev                     2.25 ns         1.60 ns           10      139.487Ki/s
ascon_xof/256/64_cv                         0.12 %          0.08 %            10            0.08%
ascon_xof/256/64_min                        1900 ns         1890 ns           10      160.974Mi/s
ascon_xof/256/64_max                        1908 ns         1896 ns           10      161.434Mi/s
ascon_prfs_verify/4_mean                    53.7 ns         53.5 ns           10      356.751Mi/s
ascon_prfs_verify/4_median                  53.6 ns         53.5 ns           10      356.715Mi/s
ascon_prfs_verify/4_stddev                 0.332 ns        0.363 ns           10      2.40873Mi/s
ascon_prfs_verify/4_cv                      0.62 %          0.68 %            10            0.68%
ascon_prfs_verify/4_min                     53.3 ns         53.1 ns           10      352.025Mi/s
ascon_prfs_verify/4_max                     54.2 ns         54.2 ns           10      359.303Mi/s
ascon_mac_verify/64_mean                     240 ns          239 ns           10      383.672Mi/s
ascon_mac_verify/64_median                   240 ns          239 ns           10      383.772Mi/s
ascon_mac_verify/64_stddev                 0.266 ns        0.244 ns           10       401.13Ki/s
ascon_mac_verify/64_cv                      0.11 %          0.10 %            10            0.10%
ascon_mac_verify/64_min                      239 ns          238 ns           10      382.756Mi/s
ascon_mac_verify/64_max                      240 ns          239 ns           10       384.06Mi/s
ascon_prfs_authenticate/1_mean              52.8 ns         52.6 ns           10      308.463Mi/s
ascon_prfs_authenticate/1_median            52.7 ns         52.5 ns           10      309.087Mi/s
ascon_prfs_authenticate/1_stddev           0.270 ns        0.309 ns           10      1.78771Mi/s
ascon_prfs_authenticate/1_cv                0.51 %          0.59 %            10            0.58%
ascon_prfs_authenticate/1_min               52.6 ns         52.4 ns           10      303.466Mi/s
ascon_prfs_authenticate/1_max               53.5 ns         53.4 ns           10      309.361Mi/s
ascon_xofa/64/64_mean                        550 ns          547 ns           10      223.193Mi/s
ascon_xofa/64/64_median                      550 ns          547 ns           10      223.262Mi/s
ascon_xofa/64/64_stddev                    0.418 ns        0.313 ns           10      130.825Ki/s
ascon_xofa/64/64_cv                         0.08 %          0.06 %            10            0.06%
ascon_xofa/64/64_min                         549 ns          547 ns           10      222.956Mi/s
ascon_xofa/64/64_max                         550 ns          548 ns           10      223.287Mi/s
ascon128a_aead_decrypt/1024/32_mean         2212 ns         2201 ns           10      457.482Mi/s
ascon128a_aead_decrypt/1024/32_median       2212 ns         2201 ns           10       457.48Mi/s
ascon128a_aead_decrypt/1024/32_stddev       1.36 ns         1.34 ns           10      285.895Ki/s
ascon128a_aead_decrypt/1024/32_cv           0.06 %          0.06 %            10            0.06%
ascon128a_aead_decrypt/1024/32_min          2211 ns         2200 ns           10      456.894Mi/s
ascon128a_aead_decrypt/1024/32_max          2216 ns         2204 ns           10      457.782Mi/s
ascon_prfs_authenticate/4_mean              52.4 ns         52.1 ns           10      366.056Mi/s
ascon_prfs_authenticate/4_median            52.3 ns         52.1 ns           10      366.093Mi/s
ascon_prfs_authenticate/4_stddev           0.071 ns        0.064 ns           10      461.174Ki/s
ascon_prfs_authenticate/4_cv                0.14 %          0.12 %            10            0.12%
ascon_prfs_authenticate/4_min               52.3 ns         52.0 ns           10      365.322Mi/s
ascon_prfs_authenticate/4_max               52.5 ns         52.2 ns           10      366.655Mi/s
ascon80pq_aead_encrypt/64/32_mean            397 ns          395 ns           10      231.628Mi/s
ascon80pq_aead_encrypt/64/32_median          397 ns          395 ns           10      231.686Mi/s
ascon80pq_aead_encrypt/64/32_stddev        0.799 ns        0.644 ns           10      386.159Ki/s
ascon80pq_aead_encrypt/64/32_cv             0.20 %          0.16 %            10            0.16%
ascon80pq_aead_encrypt/64/32_min             396 ns          394 ns           10      230.951Mi/s
ascon80pq_aead_encrypt/64/32_max             398 ns          396 ns           10      232.295Mi/s
ascon_hasha/4096_mean                      15748 ns        15672 ns           10      251.192Mi/s
ascon_hasha/4096_median                    15745 ns        15670 ns           10      251.225Mi/s
ascon_hasha/4096_stddev                     15.9 ns         12.4 ns           10      203.665Ki/s
ascon_hasha/4096_cv                         0.10 %          0.08 %            10            0.08%
ascon_hasha/4096_min                       15729 ns        15661 ns           10      250.709Mi/s
ascon_hasha/4096_max                       15783 ns        15703 ns           10      251.371Mi/s
ascon_mac_authenticate/4096_mean            6171 ns         6141 ns           10      638.625Mi/s
ascon_mac_authenticate/4096_median          6171 ns         6139 ns           10      638.825Mi/s
ascon_mac_authenticate/4096_stddev          3.65 ns         2.71 ns           10      288.236Ki/s
ascon_mac_authenticate/4096_cv              0.06 %          0.04 %            10            0.04%
ascon_mac_authenticate/4096_min             6165 ns         6138 ns           10      638.166Mi/s
ascon_mac_authenticate/4096_max             6176 ns         6145 ns           10      638.855Mi/s
ascon_hash/256_mean                         1713 ns         1705 ns           10      161.077Mi/s
ascon_hash/256_median                       1713 ns         1705 ns           10        161.1Mi/s
ascon_hash/256_stddev                       1.36 ns         1.30 ns           10      125.949Ki/s
ascon_hash/256_cv                           0.08 %          0.08 %            10            0.08%
ascon_hash/256_min                          1711 ns         1703 ns           10      160.821Mi/s
ascon_hash/256_max                          1715 ns         1708 ns           10      161.235Mi/s
ascon_hash/64_mean                           604 ns          601 ns           10      152.274Mi/s
ascon_hash/64_median                         604 ns          601 ns           10      152.291Mi/s
ascon_hash/64_stddev                       0.474 ns        0.437 ns           10      113.218Ki/s
ascon_hash/64_cv                            0.08 %          0.07 %            10            0.07%
ascon_hash/64_min                            604 ns          601 ns           10      152.091Mi/s
ascon_hash/64_max                            605 ns          602 ns           10      152.436Mi/s
ascon80pq_aead_decrypt/1024/32_mean         3139 ns         3125 ns           10      322.297Mi/s
ascon80pq_aead_decrypt/1024/32_median       3141 ns         3124 ns           10      322.333Mi/s
ascon80pq_aead_decrypt/1024/32_stddev       5.00 ns         1.02 ns           10      107.933Ki/s
ascon80pq_aead_decrypt/1024/32_cv           0.16 %          0.03 %            10            0.03%
ascon80pq_aead_decrypt/1024/32_min          3126 ns         3124 ns           10      322.016Mi/s
ascon80pq_aead_decrypt/1024/32_max          3143 ns         3127 ns           10      322.363Mi/s
ascon128_aead_encrypt/1024/32_mean          3135 ns         3119 ns           10      322.868Mi/s
ascon128_aead_encrypt/1024/32_median        3135 ns         3118 ns           10      322.981Mi/s
ascon128_aead_encrypt/1024/32_stddev        1.76 ns         2.51 ns           10      266.009Ki/s
ascon128_aead_encrypt/1024/32_cv            0.06 %          0.08 %            10            0.08%
ascon128_aead_encrypt/1024/32_min           3133 ns         3117 ns           10      322.331Mi/s
ascon128_aead_encrypt/1024/32_max           3138 ns         3124 ns           10      323.081Mi/s
ascon_xofa/1024/64_mean                     4208 ns         4187 ns           10      247.793Mi/s
ascon_xofa/1024/64_median                   4208 ns         4187 ns           10      247.841Mi/s
ascon_xofa/1024/64_stddev                   1.62 ns         1.38 ns           10      83.3247Ki/s
ascon_xofa/1024/64_cv                       0.04 %          0.03 %            10            0.03%
ascon_xofa/1024/64_min                      4205 ns         4186 ns           10      247.669Mi/s
ascon_xofa/1024/64_max                      4210 ns         4189 ns           10      247.856Mi/s
ascon_permutation<6>_mean                   24.2 ns         24.1 ns           10      1.54664Gi/s
ascon_permutation<6>_median                 24.2 ns         24.1 ns           10      1.54686Gi/s
ascon_permutation<6>_stddev                0.024 ns        0.017 ns           10      1.11125Mi/s
ascon_permutation<6>_cv                     0.10 %          0.07 %            10            0.07%
ascon_permutation<6>_min                    24.1 ns         24.1 ns           10      1.54517Gi/s
ascon_permutation<6>_max                    24.2 ns         24.1 ns           10      1.54784Gi/s
ascon128a_aead_decrypt/256/32_mean           707 ns          703 ns           10      390.579Mi/s
ascon128a_aead_decrypt/256/32_median         707 ns          703 ns           10      390.685Mi/s
ascon128a_aead_decrypt/256/32_stddev       0.965 ns        0.339 ns           10      192.525Ki/s
ascon128a_aead_decrypt/256/32_cv            0.14 %          0.05 %            10            0.05%
ascon128a_aead_decrypt/256/32_min            704 ns          703 ns           10       390.29Mi/s
ascon128a_aead_decrypt/256/32_max            707 ns          704 ns           10       390.75Mi/s
ascon128_aead_decrypt/64/32_mean             405 ns          403 ns           10      227.261Mi/s
ascon128_aead_decrypt/64/32_median           405 ns          403 ns           10       227.33Mi/s
ascon128_aead_decrypt/64/32_stddev         0.508 ns        0.492 ns           10      283.946Ki/s
ascon128_aead_decrypt/64/32_cv              0.13 %          0.12 %            10            0.12%
ascon128_aead_decrypt/64/32_min              403 ns          402 ns           10      226.593Mi/s
ascon128_aead_decrypt/64/32_max              405 ns          404 ns           10      227.579Mi/s
ascon128a_aead_encrypt/256/32_mean           686 ns          683 ns           10       402.05Mi/s
ascon128a_aead_encrypt/256/32_median         686 ns          682 ns           10      402.495Mi/s
ascon128a_aead_encrypt/256/32_stddev        3.41 ns         3.51 ns           10      2.04889Mi/s
ascon128a_aead_encrypt/256/32_cv            0.50 %          0.51 %            10            0.51%
ascon128a_aead_encrypt/256/32_min            684 ns          681 ns           10      396.758Mi/s
ascon128a_aead_encrypt/256/32_max            696 ns          692 ns           10       403.58Mi/s
ascon_mac_authenticate/256_mean              522 ns          519 ns           10      499.515Mi/s
ascon_mac_authenticate/256_median            522 ns          519 ns           10      499.793Mi/s
ascon_mac_authenticate/256_stddev           1.23 ns        0.982 ns           10      964.433Ki/s
ascon_mac_authenticate/256_cv               0.23 %          0.19 %            10            0.19%
ascon_mac_authenticate/256_min               521 ns          519 ns           10      497.401Mi/s
ascon_mac_authenticate/256_max               525 ns          522 ns           10      500.143Mi/s
ascon_xofa/4096/64_mean                    15869 ns        15797 ns           10      251.141Mi/s
ascon_xofa/4096/64_median                  15873 ns        15799 ns           10      251.117Mi/s
ascon_xofa/4096/64_stddev                   16.9 ns         10.2 ns           10       165.57Ki/s
ascon_xofa/4096/64_cv                       0.11 %          0.06 %            10            0.06%
ascon_xofa/4096/64_min                     15830 ns        15786 ns           10       250.83Mi/s
ascon_xofa/4096/64_max                     15888 ns        15817 ns           10      251.309Mi/s
ascon_mac_verify/4096_mean                  6172 ns         6142 ns           10      641.006Mi/s
ascon_mac_verify/4096_median                6167 ns         6137 ns           10      641.434Mi/s
ascon_mac_verify/4096_stddev                15.0 ns         16.4 ns           10      1.70233Mi/s
ascon_mac_verify/4096_cv                    0.24 %          0.27 %            10            0.27%
ascon_mac_verify/4096_min                   6162 ns         6134 ns           10        636.2Mi/s
ascon_mac_verify/4096_max                   6214 ns         6188 ns           10      641.774Mi/s
ascon_hasha/64_mean                          422 ns          420 ns           10      217.855Mi/s
ascon_hasha/64_median                        422 ns          420 ns           10      217.911Mi/s
ascon_hasha/64_stddev                      0.396 ns        0.430 ns           10      227.932Ki/s
ascon_hasha/64_cv                           0.09 %          0.10 %            10            0.10%
ascon_hasha/64_min                           422 ns          420 ns           10      217.347Mi/s
ascon_hasha/64_max                           423 ns          421 ns           10      218.039Mi/s
ascon128a_aead_decrypt/4096/32_mean         8259 ns         8219 ns           10      478.977Mi/s
ascon128a_aead_decrypt/4096/32_median       8260 ns         8218 ns           10      479.032Mi/s
ascon128a_aead_decrypt/4096/32_stddev       5.76 ns         6.89 ns           10      410.831Ki/s
ascon128a_aead_decrypt/4096/32_cv           0.07 %          0.08 %            10            0.08%
ascon128a_aead_decrypt/4096/32_min          8247 ns         8212 ns           10      478.432Mi/s
ascon128a_aead_decrypt/4096/32_max          8268 ns         8228 ns           10       479.39Mi/s
```

## Usage

`ascon` is a header-only C++20 library, which is pretty easy to use.

- Include proper header file(s) ( living in `include` directory ) in your header/ source file.
- Use functions/ constants living under proper namespace of interest.
- When compiling, let your compiler know where it can find header files i.e. inside `include` and `subtle/include`, by using `-I` flag.

Scheme | Header to include | Namespace of interest | Example
:-: | :-- | :-- | :-:
Ascon-128 AEAD | `include/ascon/aead/ascon128.hpp` | `ascon128_aead::` | [examples/ascon128_aead.cpp](./examples/ascon128_aead.cpp)
Ascon-128a AEAD | `include/ascon/aead/ascon128a.hpp` | `ascon128a_aead::`  | [examples/ascon128a_aead.cpp](./examples/ascon128a_aead.cpp)
Ascon-80pq AEAD | `include/ascon/aead/ascon80pq.hpp` | `ascon80pq_aead::`  | [examples/ascon80pq_aead.cpp](./examples/ascon80pq_aead.cpp)
Ascon Hash | `include/ascon/hashing/ascon_hash.hpp` | `ascon_hash::` | [examples/ascon_hash.cpp](./examples/ascon_hash.cpp)
Ascon HashA | `include/ascon/hashing/ascon_hasha.hpp` | `ascon_hasha::` | [examples/ascon_hasha.cpp](./examples/ascon_hasha.cpp)
Ascon Xof | `include/ascon/hashing/ascon_xof.hpp` | `ascon_xof::` | [examples/ascon_xof.cpp](./examples/ascon_xof.cpp)
Ascon XofA | `include/ascon/hashing/ascon_xofa.hpp` | `ascon_xofa::` | [examples/ascon_xofa.cpp](./examples/ascon_xofa.cpp)
Ascon-PRF | `include/ascon/auth/ascon_prf.hpp` | `ascon_prf::` | [examples/ascon_prf.cpp](./examples/ascon_prf.cpp)
Ascon-MAC | `include/ascon/auth/ascon_mac.hpp` | `ascon_mac::` | [examples/ascon_mac.cpp](./examples/ascon_mac.cpp)
Ascon-MAC | `include/ascon/auth/ascon_prfs.hpp` | `ascon_prfs::` | [examples/ascon_prfs.cpp](./examples/ascon_prfs.cpp)

> [!TIP]
> Don't forget to also include path ( `-I ./subtle/include` ) to dependency library `subtle`, when compiling your translation units.

Ascon permutation -based hashing schemes such as Ascon-{Hash, HashA, Xof, XofA} are all compile-time evaluable functions i.e. `constexpr`. Meaning if you've an input message, which is known at program compilation time, then it is possible to evaluate aforementioned functions on that message, during program compile-time itself. This can be useful if one needs to compute Ascon-{Hash, HashA, Xof, XofA} digests on static messages, which can be stored as part of program binary.

> [!NOTE]
> Read more about `constexpr` functions @ https://en.cppreference.com/w/cpp/language/constexpr.

```cpp
// main.cpp
// Compile: g++ -std=c++20 -Wall -O3 -I include/ -I subtle/include/ main.cpp
// Execute: ./a.out

#include "ascon/hashing/ascon_hash.hpp"
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

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon128_aead.cpp && ./a.out
Ascon-128 AEAD

Key       :	06a819d82123676245b7b88e864b01ac
Nonce     :	aaf550e27747555336e6e1efe29618dc
Data      :	a738688dfb1d2fcfab22502e11fe2559ffca02a26c60780103c88d25c611fa83
Text      :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4
Encrypted :	f5a716b9f709329a75deceeb0a72e4dbed86b89679beb99d26e1e47ff8f26f984785ac3f80677570240efb10e0bf5e93bde8c2662599052fa67026783fe2a061
Decrypted :	22bbe3e728cc9355298c614a503471b69c27a193db9331e41ba42791b63d12e8b53547daa720aa8ecef3262edd52bfd871f5425f2fc3e1c7cbc0b20a69ccc1d4

# ----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon128a_aead.cpp && ./a.out
Ascon-128a AEAD

Key       :	88119fff6f0673cfc8d0269bac8ca328
Nonce     :	0c4b7bda5d47fda1b24b06b7292dd125
Data      :	49abcffb323076de7b068b5cba32344064a9462833a32ce2f8296947d16fb708
Text      :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d
Encrypted :	d71d984670a27cb8eb033d0c10be866966315d7ad60b048fc7f5f9a90fc02534f7c807baf6f32255bd94d7872a12e47dd3bf99439da8634d996ffe1e8cf08dcf
Decrypted :	2b2e331614af85f38500a3fbe182ec4c00bd0b5a200b852f582a63249363892043c040f0950dec14038cb82a91fd057a0edb81b691fe726be9a1fa3848b38e3d

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon80pq_aead.cpp && ./a.out
Ascon-80pq AEAD

Key       :	93afc9866d8fafb4d4895a97147da2639e652407
Nonce     :	6962c11757edcfd96ac6e3312bb22615
Data      :	8c132efaa2b27795f0da45846af44f44a8fa2d98df99e301639baa0f59c57035
Text      :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864
Encrypted :	00fe776e96d074e556f84a47bc826f7be113436bda07198b3237f1f7d261ae60847609341d7c5b0c317244d9c0e3cb662e29440a43fc614d3a2a6ca488426225
Decrypted :	6d27382a7c6184fe52ea354574bfc8da49cbd7cb830183820d3e47368489428d89c4954a42ffb4f602b0cd1a9c678a25b8cc93d8b4ec39b56ea1b8157fc44864

# -----------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_hash.cpp && ./a.out
Ascon Hash

Message :	a2309f40cae3efc99941641caf1c2cddf6fcd52a031ff199dfe5f185bb5142e91539b0d6777ad7fe8c2300d42015b623517f31b5db0a94d7e3c8cb521f03aabb
Digest  :	b467a2107aa34754a8679dfbac795660a5a2be927f2b0216a8fad50202d17249

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_hasha.cpp && ./a.out
Ascon HashA

Message :	b11a401ec0ad387fdc890962e86158432ba31e50b8810e3360b4c6143a73f6f82364f6bd895938b7f0babdab065c17c7e0e7196c4a15eb345eb174f4f1da2de5
Digest  :	aa7463f3284c6b5d84aaf0c56a18ae79a2fbaf0e095111a0e65824e24892e419

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_xof.cpp && ./a.out
Ascon XOF

Message :	5265ce4d5d0b3a0d89c757e4b14049a4da449be528e9bb7606363717c16bf1f751ff64c4214aebe385ed4629b7eb14ff1a3f0ca6754ce6e54210efd33d117d41
Digest  :	65e2631e1478b8cec2fcbc8efbd954aefc4b20649d48818f06e95d355e4bda2b4d830ff05cd88f92a0d312c08e9c9959dcc8bb0e68c9ac0c0164becda6cd5acc

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_xofa.cpp && ./a.out
Ascon XOFA

Message :	6970b5465e902633d16179a2c6f68cb8ad52e853bda99cf72b9bb33bbb23d0df6b22b67e7e4dbe53e04abaa63d69ee84b0e8e87a3cdd94c9da105622ffa50755
Digest  :	52644d6ba60bd3eca3aa2dabfe69ae397ddcdd0f0abd5151bf1d0e23cb4da41b3ab75634e26bae4b19f78e95fbdd54961b35cb5c7ef3ec7639816f0833ffaea7

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_prf.cpp && ./a.out
Ascon-PRF

Key     :	518d6223f8895a8ad637e6c3fce66084
Message :	6a3fedca32ad7587663de617074eddbe64c084c658dbbb419dca2b4db5200af252a316cdcd042fdc31f11ba84a9925484d5f978e43172f3cf627a3b19e5f12f6
Tag     :	46e7936bf2468ead291854196bbaf4e00fc676a06fe33bd6326f31ac968e4aff73e8c3eb6cbc09884c226daceda36a26f0f601a93268ebcc384cc1d24baa6d5d

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_mac.cpp && ./a.out
Ascon-MAC

Key          :	53dffb5673f089f77f363fadcee2c69f
Message      :	13da8497fe16a3e4a61a937530f30ca072f470ec2a68449336264b272af354796037b8312479233f9d189bcc6e2a178b1dd5f91fc0094b59811541ac45b33b0a
Sender Tag   :	7fb21a028858927b54e148c6b25e68e2
Receiver Tag :	7fb21a028858927b54e148c6b25e68e2

# --------------

$ g++ -std=c++20 -Wall -O3 -march=native -I $ASCON_HEADERS -I $SUBTLE_HEADERS examples/ascon_prfs.cpp && ./a.out
Ascon-PRFShort

Key     :	f4c9dc526a8b03c3467abdc890575afc
Message :	f6ea9d6f4322de5c
Tag     :	3947e5220bf37c8ca807f2a1330134ad
```

> [!NOTE]
> This library doesn't expose any raw pointer + length -based interfaces, rather everything is wrapped under much safer `std::span` - which one can easily create from `std::{array, vector}` or even raw pointers and length pair. See https://en.cppreference.com/w/cpp/container/span. I made this choice because this gives us much better type safety and compile-time error reporting.
