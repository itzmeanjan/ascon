# ascon
Accelerating Ascon: Light Weight Cryptography

## Overview

`ascon` is very first cryptographic suite I decided to implement from the list of algorithms competing in final round of NIST **L**ight **W**eight **C**ryptography competition. I suggest you follow [this](https://csrc.nist.gov/Projects/Lightweight-Cryptography). Here I keep a zero-dependency, C++ header-only library implementation of `ascon` LWC suite, which should be easy to use; find examples below. Following functions are implemented

- Ascon-128 authenticated encryption/ verified decryption ( AEAD )
- Ascon-128a authenticated encryption/ verified decryption ( AEAD )
- Ascon-80pq authenticated encryption/ verified decryption ( AEAD )
- Ascon-Hash
- Ascon-HashA

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption)

> While working on this project, I've relied on Ascon [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf)

This implementation doesn't depend on anything else, except C++ standard library ( which implements C++20 specification ). I've also written Python wrapper interface to C++ implementation using `ctypes`, which is used for testing functional correctness using Known Answer Tests, provided with NIST LWC submission package of `ascon`. Benchmarking C++ interface makes use of `google-benchmark` library; see below. While it's also possible to benchmark Python wrapper API using `pytest-benchmark`; see details below.

Other than lean & simple Ascon implementation, I've also written SYCL kernels which can be used for data-parallelly computing

- Ascon-Hash of N -many independent, equal length byte slices
- Ascon-HashA of N -many independent, equal length byte slices
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-128 authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-128 verified decryption algorithm
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-128a authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-128a verified decryption algorithm
- N -many independent, non-overlapping, equal-length cipher text slices and authentication tags ( 128 -bit each ) using Ascon-80pq authenticated encryption algorithm
- N -many independent, non-overlapping, equal-length plain text slices and verification flags ( boolean ) using Ascon-80pq verified decryption algorithm

on heterogeneous accelerator devices i.e. multi-core CPUs, GPGPUs etc. Benchmark results on multiple accelerator devices can be found below. Example of using SYCL accelerated Ascon kernel API can also be found below.

## Prerequisites

- Make sure you've `g++`/ `clang++`/ `dpcpp` installed; find more about `dpcpp` [here](https://www.intel.com/content/www/us/en/developer/tools/oneapi/dpc-compiler.html), which is what I prefer using

```bash
$ dpcpp --version # I'm using
Intel(R) oneAPI DPC++/C++ Compiler 2022.0.0 (2022.0.0.20211123)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /opt/intel/oneapi/compiler/2022.0.2/linux/bin-llvm
```

```bash
$ g++ --version # used for benchmarking
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

> When targeting Nvidia CUDA devices for accelerated Ascon kernels, I'm using Intel's `clang++`, compiled from source with `--cuda` flag; find more [here](https://intel.github.io/llvm-docs/GetStartedGuide.html#prerequisites)

```bash
$ clang++ --version
clang version 15.0.0 (https://github.com/intel/llvm ff254ca03f514222a32694dd3e3b421a2903cce8)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /home/ubuntu/sycl_workspace/llvm/build/bin
```

- System development utilities like `make`, `cmake` will be required for ease of building library/ testing/ benchmarking

```bash
$ make -v
GNU Make 4.2.1
```

```bash
$ cmake  --version
cmake version 3.16.3
```

- You'll need `python3`, if you want to explore ( test/ benchmark/ use ) `ascon` Python wrapper API

```bash
$ python3 --version
Python 3.8.10
```

- Along with that you'll also need to install dependencies like

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- Actually it's better idea to use `venv` to keep this project dependencies isolated

```bash
pushd wrapper/python

python3 -m venv .
source bin/activate
python3 -m pip install -r requirements.txt
#
# ... use Python wrapper API ...
#
deactivate

popd
```

- For benchmarking C++ implementation, I use `google-benchmark`, ensure it's globally installed; follow [this](https://github.com/google/benchmark/tree/60b16f1#installation)

## Testing

- Minimal functional testing of Ascon cryptographic suite can be done using

```bash
make
```

> Above command directly tests C++ implementation

- For running detailed functional testing, using **K**nown **A**nswer **T**ests, provided with NIST submission of Ascon, consider running

```bash
make kat_test_python # needs installation of Python dependencies
```

> Last command uses Python API for testing underlying C++ implementation of Ascon cryptographic suite

## Benchmarking

There're two ways to benchmark all implemented routines of Ascon cryptographic suite. Following functions are benchmarked

- Ascon-128 ( encrypt/ decrypt )
- Ascon-128a ( encrypt/ decrypt )
- Ascon-80pq ( encrypt/ decrypt )
- Ascon-Hash
- Ascon-HashA

---

1. For benchmarking C++ API, `google-benchmark` is used ( make sure it's available ), issue

```bash
make bench_cpp
```

### On AWS Graviton3 ( when compiled with `g++` )

```bash
2022-07-21T07:15:05+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.19, 0.06, 0.02
--------------------------------------------------------------------------------
Benchmark                      Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------
ascon_permutation<1>        6.45 ns         6.45 ns    108344958 bytes_per_second=5.77432G/s
ascon_permutation<6>        27.7 ns         27.7 ns     25268513 bytes_per_second=1.34437G/s
ascon_permutation<8>        35.5 ns         35.5 ns     19694314 bytes_per_second=1073.64M/s
ascon_permutation<12>       52.5 ns         52.5 ns     13310985 bytes_per_second=726.117M/s
ascon_hash/64                657 ns          657 ns      1058710 bytes_per_second=92.8448M/s
ascon_hash/128              1068 ns         1068 ns       656094 bytes_per_second=114.322M/s
ascon_hash/256              1882 ns         1882 ns       372117 bytes_per_second=129.696M/s
ascon_hash/512              3505 ns         3505 ns       199643 bytes_per_second=139.321M/s
ascon_hash/1024             6744 ns         6744 ns       103777 bytes_per_second=144.799M/s
ascon_hash/2048            13227 ns        13227 ns        52922 bytes_per_second=147.666M/s
ascon_hash/4096            26222 ns        26221 ns        26724 bytes_per_second=148.976M/s
ascon_hash_a/64              458 ns          458 ns      1526933 bytes_per_second=133.267M/s
ascon_hash_a/128             729 ns          729 ns       960932 bytes_per_second=167.561M/s
ascon_hash_a/256            1272 ns         1272 ns       549941 bytes_per_second=191.875M/s
ascon_hash_a/512            2359 ns         2359 ns       296775 bytes_per_second=206.985M/s
ascon_hash_a/1024           4542 ns         4542 ns       154438 bytes_per_second=214.992M/s
ascon_hash_a/2048           8876 ns         8876 ns        78871 bytes_per_second=220.053M/s
ascon_hash_a/4096          17574 ns        17573 ns        39850 bytes_per_second=222.284M/s
ascon_128_enc/64             548 ns          548 ns      1277822 bytes_per_second=222.862M/s
ascon_128_enc/128            757 ns          757 ns       924253 bytes_per_second=241.74M/s
ascon_128_enc/256           1176 ns         1176 ns       594976 bytes_per_second=259.519M/s
ascon_128_enc/512           2010 ns         2010 ns       348001 bytes_per_second=273.256M/s
ascon_128_enc/1024          3683 ns         3683 ns       190494 bytes_per_second=281.717M/s
ascon_128_enc/2048          7004 ns         7004 ns        99966 bytes_per_second=287.573M/s
ascon_128_enc/4096         13644 ns        13644 ns        51300 bytes_per_second=290.772M/s
ascon_128_dec/64             546 ns          546 ns      1281025 bytes_per_second=223.483M/s
ascon_128_dec/128            754 ns          754 ns       927849 bytes_per_second=242.796M/s
ascon_128_dec/256           1169 ns         1169 ns       598824 bytes_per_second=261.116M/s
ascon_128_dec/512           1998 ns         1998 ns       350409 bytes_per_second=274.979M/s
ascon_128_dec/1024          3654 ns         3654 ns       191535 bytes_per_second=283.934M/s
ascon_128_dec/2048          6970 ns         6970 ns       100425 bytes_per_second=288.975M/s
ascon_128_dec/4096         13604 ns        13604 ns        51454 bytes_per_second=291.625M/s
ascon_128a_enc/64            425 ns          425 ns      1648774 bytes_per_second=287.451M/s
ascon_128a_enc/128           568 ns          568 ns      1232446 bytes_per_second=322.498M/s
ascon_128a_enc/256           854 ns          854 ns       819696 bytes_per_second=357.366M/s
ascon_128a_enc/512          1426 ns         1426 ns       490644 bytes_per_second=385.103M/s
ascon_128a_enc/1024         2573 ns         2573 ns       272066 bytes_per_second=403.225M/s
ascon_128a_enc/2048         4864 ns         4864 ns       143942 bytes_per_second=414.123M/s
ascon_128a_enc/4096         9446 ns         9445 ns        74128 bytes_per_second=420.03M/s
ascon_128a_dec/64            423 ns          423 ns      1652774 bytes_per_second=288.4M/s
ascon_128a_dec/128           566 ns          566 ns      1236571 bytes_per_second=323.575M/s
ascon_128a_dec/256           852 ns          852 ns       821851 bytes_per_second=358.159M/s
ascon_128a_dec/512          1424 ns         1424 ns       491701 bytes_per_second=385.801M/s
ascon_128a_dec/1024         2569 ns         2569 ns       272539 bytes_per_second=403.93M/s
ascon_128a_dec/2048         4858 ns         4858 ns       144084 bytes_per_second=414.596M/s
ascon_128a_dec/4096         9433 ns         9433 ns        74163 bytes_per_second=420.573M/s
ascon_80pq_enc/64            550 ns          550 ns      1272466 bytes_per_second=221.962M/s
ascon_80pq_enc/128           761 ns          761 ns       920701 bytes_per_second=240.719M/s
ascon_80pq_enc/256          1183 ns         1183 ns       591833 bytes_per_second=258.012M/s
ascon_80pq_enc/512          2026 ns         2026 ns       345467 bytes_per_second=271.074M/s
ascon_80pq_enc/1024         3712 ns         3712 ns       188569 bytes_per_second=279.517M/s
ascon_80pq_enc/2048         7083 ns         7082 ns        98821 bytes_per_second=284.39M/s
ascon_80pq_enc/4096        13826 ns        13825 ns        50651 bytes_per_second=286.96M/s
ascon_80pq_dec/64            543 ns          543 ns      1288762 bytes_per_second=224.796M/s
ascon_80pq_dec/128           750 ns          750 ns       933775 bytes_per_second=244.145M/s
ascon_80pq_dec/256          1163 ns         1163 ns       602211 bytes_per_second=262.338M/s
ascon_80pq_dec/512          1990 ns         1990 ns       351848 bytes_per_second=276.028M/s
ascon_80pq_dec/1024         3642 ns         3642 ns       192259 bytes_per_second=284.868M/s
ascon_80pq_dec/2048         6947 ns         6947 ns       100790 bytes_per_second=289.944M/s
ascon_80pq_dec/4096        13547 ns        13547 ns        51648 bytes_per_second=292.857M/s
```

### On AWS Graviton3 ( when compiled with `clang++` )

```bash
2022-07-21T07:16:32+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.36, 0.18, 0.07
--------------------------------------------------------------------------------
Benchmark                      Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------
ascon_permutation<1>        4.71 ns         4.71 ns    148889559 bytes_per_second=7.91553G/s
ascon_permutation<6>        22.9 ns         22.9 ns     30528543 bytes_per_second=1.62388G/s
ascon_permutation<8>        29.9 ns         29.9 ns     23394399 bytes_per_second=1.24542G/s
ascon_permutation<12>       44.5 ns         44.5 ns     15737320 bytes_per_second=857.81M/s
ascon_hash/64                563 ns          563 ns      1243303 bytes_per_second=108.494M/s
ascon_hash/128               909 ns          909 ns       770301 bytes_per_second=134.316M/s
ascon_hash/256              1603 ns         1603 ns       437564 bytes_per_second=152.339M/s
ascon_hash/512              2982 ns         2982 ns       234739 bytes_per_second=163.752M/s
ascon_hash/1024             5750 ns         5750 ns       121724 bytes_per_second=169.849M/s
ascon_hash/2048            11298 ns        11298 ns        61956 bytes_per_second=172.874M/s
ascon_hash/4096            22358 ns        22358 ns        31343 bytes_per_second=174.715M/s
ascon_hash_a/64              393 ns          393 ns      1787023 bytes_per_second=155.457M/s
ascon_hash_a/128             624 ns          623 ns      1123691 bytes_per_second=195.783M/s
ascon_hash_a/256            1085 ns         1085 ns       645070 bytes_per_second=225.026M/s
ascon_hash_a/512            2010 ns         2010 ns       348164 bytes_per_second=242.974M/s
ascon_hash_a/1024           3857 ns         3857 ns       181447 bytes_per_second=253.224M/s
ascon_hash_a/2048           7548 ns         7548 ns        92732 bytes_per_second=258.754M/s
ascon_hash_a/4096          14937 ns        14937 ns        46861 bytes_per_second=261.514M/s
ascon_128_enc/64             465 ns          465 ns      1506418 bytes_per_second=262.746M/s
ascon_128_enc/128            640 ns          640 ns      1093731 bytes_per_second=285.974M/s
ascon_128_enc/256            991 ns          991 ns       706150 bytes_per_second=307.847M/s
ascon_128_enc/512           1693 ns         1693 ns       413609 bytes_per_second=324.403M/s
ascon_128_enc/1024          3099 ns         3099 ns       225991 bytes_per_second=334.865M/s
ascon_128_enc/2048          5911 ns         5910 ns       118480 bytes_per_second=340.782M/s
ascon_128_enc/4096         11485 ns        11485 ns        60883 bytes_per_second=345.436M/s
ascon_128_dec/64             462 ns          462 ns      1515397 bytes_per_second=264.001M/s
ascon_128_dec/128            637 ns          637 ns      1098882 bytes_per_second=287.313M/s
ascon_128_dec/256            987 ns          987 ns       709105 bytes_per_second=309.046M/s
ascon_128_dec/512           1693 ns         1693 ns       414061 bytes_per_second=324.479M/s
ascon_128_dec/1024          3093 ns         3093 ns       226253 bytes_per_second=335.426M/s
ascon_128_dec/2048          5895 ns         5895 ns       118743 bytes_per_second=341.693M/s
ascon_128_dec/4096         11495 ns        11495 ns        60929 bytes_per_second=345.146M/s
ascon_128a_enc/64            362 ns          362 ns      1933645 bytes_per_second=337.294M/s
ascon_128a_enc/128           485 ns          485 ns      1448813 bytes_per_second=377.322M/s
ascon_128a_enc/256           731 ns          731 ns       957044 bytes_per_second=417.662M/s
ascon_128a_enc/512          1224 ns         1224 ns       571751 bytes_per_second=448.938M/s
ascon_128a_enc/1024         2203 ns         2203 ns       317633 bytes_per_second=470.933M/s
ascon_128a_enc/2048         4169 ns         4169 ns       168287 bytes_per_second=483.129M/s
ascon_128a_enc/4096         8102 ns         8101 ns        86397 bytes_per_second=489.703M/s
ascon_128a_dec/64            358 ns          358 ns      1951605 bytes_per_second=340.524M/s
ascon_128a_dec/128           481 ns          481 ns      1454865 bytes_per_second=380.672M/s
ascon_128a_dec/256           728 ns          728 ns       961671 bytes_per_second=419.394M/s
ascon_128a_dec/512          1220 ns         1220 ns       575188 bytes_per_second=450.377M/s
ascon_128a_dec/1024         2210 ns         2210 ns       317172 bytes_per_second=469.469M/s
ascon_128a_dec/2048         4181 ns         4181 ns       167411 bytes_per_second=481.756M/s
ascon_128a_dec/4096         8134 ns         8134 ns        86079 bytes_per_second=487.762M/s
ascon_80pq_enc/64            466 ns          466 ns      1502865 bytes_per_second=262.046M/s
ascon_80pq_enc/128           640 ns          640 ns      1094553 bytes_per_second=286.017M/s
ascon_80pq_enc/256           989 ns          989 ns       708130 bytes_per_second=308.472M/s
ascon_80pq_enc/512          1689 ns         1689 ns       414574 bytes_per_second=325.179M/s
ascon_80pq_enc/1024         3082 ns         3081 ns       227297 bytes_per_second=336.727M/s
ascon_80pq_enc/2048         5872 ns         5872 ns       119313 bytes_per_second=343.025M/s
ascon_80pq_enc/4096        11442 ns        11442 ns        61157 bytes_per_second=346.743M/s
ascon_80pq_dec/64            462 ns          462 ns      1516807 bytes_per_second=264.442M/s
ascon_80pq_dec/128           636 ns          636 ns      1100730 bytes_per_second=287.783M/s
ascon_80pq_dec/256           985 ns          985 ns       710991 bytes_per_second=309.94M/s
ascon_80pq_dec/512          1686 ns         1686 ns       415117 bytes_per_second=325.762M/s
ascon_80pq_dec/1024         3084 ns         3084 ns       226980 bytes_per_second=336.464M/s
ascon_80pq_dec/2048         5879 ns         5879 ns       119076 bytes_per_second=342.602M/s
ascon_80pq_dec/4096        11469 ns        11469 ns        61025 bytes_per_second=345.921M/s
```

### On AWS Graviton2 ( ARM Cortex-A72 ) ( when compiled with `g++` )

```bash
2022-07-21T07:12:00+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.19, 0.08, 0.03
--------------------------------------------------------------------------------
Benchmark                      Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------
ascon_permutation<1>        11.3 ns         11.3 ns     61845351 bytes_per_second=3.29313G/s
ascon_permutation<6>        43.9 ns         43.9 ns     15929955 bytes_per_second=868.099M/s
ascon_permutation<8>        64.0 ns         64.0 ns     10944632 bytes_per_second=596.448M/s
ascon_permutation<12>       93.5 ns         93.5 ns      7482748 bytes_per_second=407.808M/s
ascon_hash/64               1184 ns         1184 ns       591919 bytes_per_second=51.5647M/s
ascon_hash/128              1902 ns         1902 ns       368505 bytes_per_second=64.1775M/s
ascon_hash/256              3338 ns         3338 ns       209905 bytes_per_second=73.1431M/s
ascon_hash/512              6204 ns         6202 ns       112865 bytes_per_second=78.7295M/s
ascon_hash/1024            11939 ns        11938 ns        58634 bytes_per_second=81.7995M/s
ascon_hash/2048            23411 ns        23411 ns        29902 bytes_per_second=83.428M/s
ascon_hash/4096            46365 ns        46362 ns        15101 bytes_per_second=84.2549M/s
ascon_hash_a/64              818 ns          818 ns       855744 bytes_per_second=74.6203M/s
ascon_hash_a/128            1295 ns         1295 ns       540611 bytes_per_second=94.2769M/s
ascon_hash_a/256            2248 ns         2248 ns       311298 bytes_per_second=108.581M/s
ascon_hash_a/512            4156 ns         4156 ns       168434 bytes_per_second=117.488M/s
ascon_hash_a/1024           7971 ns         7971 ns        87817 bytes_per_second=122.517M/s
ascon_hash_a/2048          15601 ns        15600 ns        44870 bytes_per_second=125.196M/s
ascon_hash_a/4096          30860 ns        30860 ns        22682 bytes_per_second=126.58M/s
ascon_128_enc/64             877 ns          877 ns       798004 bytes_per_second=139.168M/s
ascon_128_enc/128           1208 ns         1208 ns       579547 bytes_per_second=151.6M/s
ascon_128_enc/256           1869 ns         1869 ns       374498 bytes_per_second=163.272M/s
ascon_128_enc/512           3199 ns         3199 ns       218802 bytes_per_second=171.699M/s
ascon_128_enc/1024          5845 ns         5845 ns       119765 bytes_per_second=177.531M/s
ascon_128_enc/2048         11136 ns        11135 ns        62861 bytes_per_second=180.878M/s
ascon_128_enc/4096         21717 ns        21717 ns        32232 bytes_per_second=182.681M/s
ascon_128_dec/64             881 ns          881 ns       794471 bytes_per_second=138.553M/s
ascon_128_dec/128           1212 ns         1212 ns       577641 bytes_per_second=151.11M/s
ascon_128_dec/256           1873 ns         1873 ns       373711 bytes_per_second=162.932M/s
ascon_128_dec/512           3200 ns         3200 ns       218736 bytes_per_second=171.658M/s
ascon_128_dec/1024          5845 ns         5845 ns       119749 bytes_per_second=177.506M/s
ascon_128_dec/2048         11137 ns        11136 ns        62857 bytes_per_second=180.865M/s
ascon_128_dec/4096         21718 ns        21717 ns        32231 bytes_per_second=182.677M/s
ascon_128a_enc/64            713 ns          713 ns       975745 bytes_per_second=171.101M/s
ascon_128a_enc/128           944 ns          944 ns       741379 bytes_per_second=193.926M/s
ascon_128a_enc/256          1411 ns         1411 ns       496233 bytes_per_second=216.343M/s
ascon_128a_enc/512          2344 ns         2344 ns       298696 bytes_per_second=234.391M/s
ascon_128a_enc/1024         4209 ns         4209 ns       166298 bytes_per_second=246.503M/s
ascon_128a_enc/2048         7941 ns         7941 ns        88147 bytes_per_second=253.645M/s
ascon_128a_enc/4096        15406 ns        15406 ns        45438 bytes_per_second=257.518M/s
ascon_128a_dec/64            700 ns          700 ns      1000481 bytes_per_second=174.476M/s
ascon_128a_dec/128           945 ns          945 ns       741028 bytes_per_second=193.844M/s
ascon_128a_dec/256          1418 ns         1418 ns       493639 bytes_per_second=215.221M/s
ascon_128a_dec/512          2365 ns         2365 ns       296006 bytes_per_second=232.295M/s
ascon_128a_dec/1024         4258 ns         4258 ns       164385 bytes_per_second=243.665M/s
ascon_128a_dec/2048         8046 ns         8046 ns        87000 bytes_per_second=250.345M/s
ascon_128a_dec/4096        15619 ns        15619 ns        44815 bytes_per_second=253.998M/s
ascon_80pq_enc/64            887 ns          887 ns       789008 bytes_per_second=137.595M/s
ascon_80pq_enc/128          1221 ns         1221 ns       573148 bytes_per_second=149.927M/s
ascon_80pq_enc/256          1890 ns         1890 ns       370441 bytes_per_second=161.5M/s
ascon_80pq_enc/512          3234 ns         3234 ns       216477 bytes_per_second=169.877M/s
ascon_80pq_enc/1024         5907 ns         5907 ns       118505 bytes_per_second=175.658M/s
ascon_80pq_enc/2048        11253 ns        11253 ns        62200 bytes_per_second=178.984M/s
ascon_80pq_enc/4096        21947 ns        21947 ns        31894 bytes_per_second=180.77M/s
ascon_80pq_dec/64            877 ns          877 ns       797997 bytes_per_second=139.164M/s
ascon_80pq_dec/128          1201 ns         1201 ns       582898 bytes_per_second=152.481M/s
ascon_80pq_dec/256          1848 ns         1848 ns       378729 bytes_per_second=165.11M/s
ascon_80pq_dec/512          3150 ns         3150 ns       222218 bytes_per_second=174.383M/s
ascon_80pq_dec/1024         5740 ns         5740 ns       121944 bytes_per_second=180.769M/s
ascon_80pq_dec/2048        10919 ns        10919 ns        64101 bytes_per_second=184.46M/s
ascon_80pq_dec/4096        21278 ns        21278 ns        32897 bytes_per_second=186.449M/s
```

### On AWS Graviton2 ( ARM Cortex-A72 ) ( when compiled with `clang++` )

```bash
2022-07-21T07:22:19+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.04, 0.04
--------------------------------------------------------------------------------
Benchmark                      Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------
ascon_permutation<1>        10.4 ns         10.4 ns     67013775 bytes_per_second=3.56758G/s
ascon_permutation<6>        50.5 ns         50.5 ns     13866692 bytes_per_second=755.842M/s
ascon_permutation<8>        66.1 ns         66.1 ns     10584382 bytes_per_second=576.831M/s
ascon_permutation<12>       96.2 ns         96.2 ns      7279943 bytes_per_second=396.731M/s
ascon_hash/64               1255 ns         1255 ns       557599 bytes_per_second=48.6386M/s
ascon_hash/128              2014 ns         2014 ns       347720 bytes_per_second=60.6239M/s
ascon_hash/256              3531 ns         3531 ns       198259 bytes_per_second=69.1467M/s
ascon_hash/512              6571 ns         6570 ns       106482 bytes_per_second=74.3145M/s
ascon_hash/1024            12636 ns        12636 ns        55396 bytes_per_second=77.2853M/s
ascon_hash/2048            24783 ns        24783 ns        28247 bytes_per_second=78.8101M/s
ascon_hash/4096            49060 ns        49058 ns        14267 bytes_per_second=79.6246M/s
ascon_hash_a/64              871 ns          871 ns       803624 bytes_per_second=70.0742M/s
ascon_hash_a/128            1379 ns         1379 ns       507529 bytes_per_second=88.5092M/s
ascon_hash_a/256            2396 ns         2396 ns       292211 bytes_per_second=101.916M/s
ascon_hash_a/512            4428 ns         4428 ns       158072 bytes_per_second=110.266M/s
ascon_hash_a/1024           8494 ns         8494 ns        82414 bytes_per_second=114.977M/s
ascon_hash_a/2048          16624 ns        16624 ns        42106 bytes_per_second=117.488M/s
ascon_hash_a/4096          32887 ns        32886 ns        21286 bytes_per_second=118.782M/s
ascon_128_enc/64            1043 ns         1043 ns       670876 bytes_per_second=116.995M/s
ascon_128_enc/128           1437 ns         1437 ns       487233 bytes_per_second=127.446M/s
ascon_128_enc/256           2223 ns         2223 ns       314838 bytes_per_second=137.259M/s
ascon_128_enc/512           3797 ns         3797 ns       184372 bytes_per_second=144.682M/s
ascon_128_enc/1024          6944 ns         6943 ns       100812 bytes_per_second=149.436M/s
ascon_128_enc/2048         13237 ns        13237 ns        52881 bytes_per_second=152.167M/s
ascon_128_enc/4096         25824 ns        25824 ns        27105 bytes_per_second=153.627M/s
ascon_128_dec/64            1035 ns         1035 ns       676551 bytes_per_second=117.986M/s
ascon_128_dec/128           1425 ns         1424 ns       491408 bytes_per_second=128.542M/s
ascon_128_dec/256           2204 ns         2204 ns       317581 bytes_per_second=138.455M/s
ascon_128_dec/512           3764 ns         3764 ns       185997 bytes_per_second=145.958M/s
ascon_128_dec/1024          6882 ns         6882 ns       101709 bytes_per_second=150.766M/s
ascon_128_dec/2048         13120 ns        13120 ns        53353 bytes_per_second=153.519M/s
ascon_128_dec/4096         25595 ns        25595 ns        27349 bytes_per_second=155.005M/s
ascon_128a_enc/64            814 ns          814 ns       859175 bytes_per_second=149.91M/s
ascon_128a_enc/128          1086 ns         1086 ns       644568 bytes_per_second=168.614M/s
ascon_128a_enc/256          1632 ns         1632 ns       428793 bytes_per_second=186.949M/s
ascon_128a_enc/512          2725 ns         2725 ns       256845 bytes_per_second=201.563M/s
ascon_128a_enc/1024         4911 ns         4911 ns       142529 bytes_per_second=211.27M/s
ascon_128a_enc/2048         9283 ns         9283 ns        75405 bytes_per_second=216.977M/s
ascon_128a_enc/4096        18027 ns        18027 ns        38831 bytes_per_second=220.079M/s
ascon_128a_dec/64            798 ns          798 ns       877718 bytes_per_second=153.062M/s
ascon_128a_dec/128          1078 ns         1078 ns       649510 bytes_per_second=169.902M/s
ascon_128a_dec/256          1624 ns         1624 ns       430982 bytes_per_second=187.893M/s
ascon_128a_dec/512          2717 ns         2717 ns       257633 bytes_per_second=202.17M/s
ascon_128a_dec/1024         4903 ns         4903 ns       142770 bytes_per_second=211.624M/s
ascon_128a_dec/2048         9275 ns         9275 ns        75470 bytes_per_second=217.164M/s
ascon_128a_dec/4096        18019 ns        18018 ns        38849 bytes_per_second=220.179M/s
ascon_80pq_enc/64           1045 ns         1045 ns       669776 bytes_per_second=116.804M/s
ascon_80pq_enc/128          1438 ns         1438 ns       486629 bytes_per_second=127.296M/s
ascon_80pq_enc/256          2225 ns         2225 ns       314569 bytes_per_second=137.153M/s
ascon_80pq_enc/512          3798 ns         3798 ns       184286 bytes_per_second=144.62M/s
ascon_80pq_enc/1024         6946 ns         6945 ns       100786 bytes_per_second=149.392M/s
ascon_80pq_enc/2048        13238 ns        13238 ns        52876 bytes_per_second=152.148M/s
ascon_80pq_enc/4096        25826 ns        25825 ns        27105 bytes_per_second=153.619M/s
ascon_80pq_dec/64           1035 ns         1035 ns       676210 bytes_per_second=117.924M/s
ascon_80pq_dec/128          1425 ns         1425 ns       491204 bytes_per_second=128.492M/s
ascon_80pq_dec/256          2205 ns         2205 ns       317519 bytes_per_second=138.425M/s
ascon_80pq_dec/512          3764 ns         3764 ns       185974 bytes_per_second=145.941M/s
ascon_80pq_dec/1024         6883 ns         6883 ns       101699 bytes_per_second=150.749M/s
ascon_80pq_dec/2048        13121 ns        13120 ns        53353 bytes_per_second=153.515M/s
ascon_80pq_dec/4096        25596 ns        25595 ns        27347 bytes_per_second=155.001M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
2022-07-21T11:06:38+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.80, 2.10, 2.14
--------------------------------------------------------------------------------
Benchmark                      Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------
ascon_permutation<1>        4.61 ns         4.60 ns    132048065 bytes_per_second=8.08996G/s
ascon_permutation<6>        24.2 ns         24.1 ns     28634424 bytes_per_second=1.54258G/s
ascon_permutation<8>        31.7 ns         31.6 ns     22162279 bytes_per_second=1.17733G/s
ascon_permutation<12>       48.1 ns         47.7 ns     14624465 bytes_per_second=799.257M/s
ascon_hash/64                565 ns          565 ns      1215299 bytes_per_second=108.119M/s
ascon_hash/128               948 ns          946 ns       722320 bytes_per_second=129.006M/s
ascon_hash/256              2026 ns         1972 ns       357912 bytes_per_second=123.822M/s
ascon_hash/512              3460 ns         3431 ns       209054 bytes_per_second=142.326M/s
ascon_hash/1024             6544 ns         6490 ns       105225 bytes_per_second=150.474M/s
ascon_hash/2048            12293 ns        12290 ns        55680 bytes_per_second=158.926M/s
ascon_hash/4096            24107 ns        24098 ns        28431 bytes_per_second=162.096M/s
ascon_hash_a/64              412 ns          404 ns      1824128 bytes_per_second=150.97M/s
ascon_hash_a/128             638 ns          635 ns      1018300 bytes_per_second=192.086M/s
ascon_hash_a/256            1196 ns         1184 ns       618309 bytes_per_second=206.262M/s
ascon_hash_a/512            2192 ns         2184 ns       246648 bytes_per_second=223.596M/s
ascon_hash_a/1024           4118 ns         4115 ns       168338 bytes_per_second=237.318M/s
ascon_hash_a/2048           8593 ns         8519 ns        85708 bytes_per_second=229.256M/s
ascon_hash_a/4096          15917 ns        15895 ns        38747 bytes_per_second=245.756M/s
ascon_128_enc/64             522 ns          521 ns      1310395 bytes_per_second=234.191M/s
ascon_128_enc/128            812 ns          796 ns       922278 bytes_per_second=230.156M/s
ascon_128_enc/256           1148 ns         1147 ns       556735 bytes_per_second=266.057M/s
ascon_128_enc/512           2018 ns         2007 ns       356354 bytes_per_second=273.703M/s
ascon_128_enc/1024          3667 ns         3642 ns       180238 bytes_per_second=284.894M/s
ascon_128_enc/2048          6801 ns         6795 ns        98490 bytes_per_second=296.416M/s
ascon_128_enc/4096         13796 ns        13644 ns        52347 bytes_per_second=290.768M/s
ascon_128_dec/64             567 ns          555 ns      1227769 bytes_per_second=219.832M/s
ascon_128_dec/128            791 ns          776 ns       895393 bytes_per_second=236.05M/s
ascon_128_dec/256           1149 ns         1144 ns       570744 bytes_per_second=266.689M/s
ascon_128_dec/512           2083 ns         2064 ns       343833 bytes_per_second=266.13M/s
ascon_128_dec/1024          3949 ns         3866 ns       156474 bytes_per_second=268.424M/s
ascon_128_dec/2048          7368 ns         7238 ns        96693 bytes_per_second=278.263M/s
ascon_128_dec/4096         13763 ns        13640 ns        49096 bytes_per_second=290.865M/s
ascon_128a_enc/64            435 ns          430 ns      1619044 bytes_per_second=283.621M/s
ascon_128a_enc/128           572 ns          567 ns      1249331 bytes_per_second=323.215M/s
ascon_128a_enc/256           892 ns          872 ns       799607 bytes_per_second=349.958M/s
ascon_128a_enc/512          1362 ns         1358 ns       496095 bytes_per_second=404.428M/s
ascon_128a_enc/1024         2659 ns         2618 ns       239361 bytes_per_second=396.327M/s
ascon_128a_enc/2048         4798 ns         4750 ns       148233 bytes_per_second=424.031M/s
ascon_128a_enc/4096         9726 ns         9632 ns        80161 bytes_per_second=411.871M/s
ascon_128a_dec/64            434 ns          433 ns      1618740 bytes_per_second=281.921M/s
ascon_128a_dec/128           637 ns          629 ns      1234742 bytes_per_second=291.239M/s
ascon_128a_dec/256           812 ns          811 ns       830792 bytes_per_second=376.103M/s
ascon_128a_dec/512          1338 ns         1336 ns       516430 bytes_per_second=411.037M/s
ascon_128a_dec/1024         2392 ns         2390 ns       291742 bytes_per_second=434.187M/s
ascon_128a_dec/2048         4699 ns         4654 ns       155650 bytes_per_second=432.742M/s
ascon_128a_dec/4096         8852 ns         8817 ns        75745 bytes_per_second=449.935M/s
ascon_80pq_enc/64            536 ns          534 ns      1285843 bytes_per_second=228.632M/s
ascon_80pq_enc/128           740 ns          738 ns       930888 bytes_per_second=248.068M/s
ascon_80pq_enc/256          1224 ns         1210 ns       576910 bytes_per_second=252.172M/s
ascon_80pq_enc/512          2079 ns         2054 ns       342017 bytes_per_second=267.485M/s
ascon_80pq_enc/1024         3569 ns         3566 ns       187809 bytes_per_second=290.944M/s
ascon_80pq_enc/2048         6942 ns         6910 ns       101250 bytes_per_second=291.479M/s
ascon_80pq_enc/4096        13495 ns        13440 ns        51448 bytes_per_second=295.191M/s
ascon_80pq_dec/64            528 ns          527 ns      1323927 bytes_per_second=231.803M/s
ascon_80pq_dec/128           729 ns          727 ns       946778 bytes_per_second=251.752M/s
ascon_80pq_dec/256          1122 ns         1120 ns       606176 bytes_per_second=272.393M/s
ascon_80pq_dec/512          1914 ns         1913 ns       355664 bytes_per_second=287.079M/s
ascon_80pq_dec/1024         3627 ns         3605 ns       193776 bytes_per_second=287.818M/s
ascon_80pq_dec/2048         6903 ns         6879 ns        95770 bytes_per_second=292.805M/s
ascon_80pq_dec/4096        13969 ns        13847 ns        51394 bytes_per_second=286.517M/s
```

---

2. And for benchmarking `ascon` Python wrapper API, `pytest-benchmark` is used

```bash
make bench_python
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```bash
------------------------------------------------------------------------------------------- benchmark: 8 tests -------------------------------------------------------------------------------------------
Name (time in us)                     Min                   Max               Mean             StdDev             Median               IQR            Outliers  OPS (Kops/s)            Rounds  Iterations
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_bench_ascon_hasha             9.0260 (1.0)      9,428.6130 (53.69)    11.2271 (1.0)      78.9193 (7.59)      9.5350 (1.0)      0.3335 (1.0)       12;1687       89.0702 (1.0)       14488           1
test_bench_ascon_hash             12.1540 (1.35)       175.6240 (1.0)      13.9209 (1.24)     10.8109 (1.04)     12.6490 (1.33)     0.4205 (1.26)         3;34       71.8345 (0.81)        239           1
test_bench_ascon_128_encrypt      18.0770 (2.00)       264.0930 (1.50)     21.0252 (1.87)     10.3964 (1.0)      19.2420 (2.02)     0.6220 (1.87)     439;1073       47.5620 (0.53)      12052           1
test_bench_ascon_128a_encrypt     18.2200 (2.02)       253.1850 (1.44)     22.0808 (1.97)     13.0963 (1.26)     19.2890 (2.02)     0.6680 (2.00)      398;842       45.2882 (0.51)       7285           1
test_bench_ascon_80pq_encrypt     18.5210 (2.05)       248.9030 (1.42)     22.0310 (1.96)     11.4594 (1.10)     19.9060 (2.09)     0.6660 (2.00)     512;1101       45.3906 (0.51)      11929           1
test_bench_ascon_128_decrypt      18.6030 (2.06)       346.4190 (1.97)     22.3230 (1.99)     11.5591 (1.11)     20.0910 (2.11)     0.6400 (1.92)    1484;3262       44.7968 (0.50)      30953           1
test_bench_ascon_128a_decrypt     18.8170 (2.08)       370.0150 (2.11)     22.3928 (1.99)     12.3355 (1.19)     19.9650 (2.09)     0.6365 (1.91)    1429;3450       44.6572 (0.50)      30564           1
test_bench_ascon_80pq_decrypt     19.4510 (2.15)       283.0880 (1.61)     23.0147 (2.05)     11.7192 (1.13)     20.6670 (2.17)     0.5460 (1.64)    1365;3571       43.4505 (0.49)      29339           1
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Legend:
  Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
  OPS: Operations Per Second, computed as 1 / Mean
===================================================================================== 8 passed, 5 deselected in 6.34s ======================================================================================
```

## Usage

### Basic Ascon API

`ascon` being a header-only C++ library, it's pretty easy to start using its C++ API. Just include the header file ( i.e. `include/ascon.hpp` ) and use functions living inside `ascon::` namespace. Namespace like `ascon_utils::` might also be of your interest, which has some utility routines implemented.

```cpp
// ascon_hash.cpp
// see https://github.com/itzmeanjan/ascon/blob/2e45d60/example/ascon_hash.cpp

#include "ascon.hpp"
#include <iostream>

int
main(int argc, char** argv)
{
  constexpr size_t msg_len = 1024; // bytes
  constexpr size_t out_len = 32;   // bytes

  // acquire resources
  uint8_t* msg = static_cast<uint8_t*>(malloc(msg_len)); // input
  uint8_t* out = static_cast<uint8_t*>(malloc(out_len)); // digest

  // prepare input
#pragma unroll 8
  for (size_t i = 0; i < msg_len; i++) {
    msg[i] = static_cast<uint8_t>(i);
  }

  // compute digest using Ascon-Hash
  ascon::hash(msg, msg_len, out);
  // digest as hex string
  const std::string digest = ascon_utils::tohex(out, out_len);

  std::cout << "Ascon-Hash digest :\t" << digest << std::endl;

  // deallocate resources
  free(msg);
  free(out);

  return EXIT_SUCCESS;
}
```

Now you can compile & run

```bash
$ dpcpp -Wall -std=c++20 -O3 -I./include example/ascon_hash.cpp && ./a.out

Ascon-Hash digest :     2eb89744de7f9a6f47d53db756bb2f67b127da96762a1c47a5d7bfc1f7273f5c
```

See example of using

- [Ascon-Hash API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hash.cpp)
- [Ascon-HashA API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128a.cpp)
- [Ascon-80pq authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/b680d4b/example/ascon_80pq.cpp)

---

### Accelerated Ascon Kernel API

For using accelerated Ascon API, where data-parallel variants of all basic Ascon cryptographic functions are written, using SYCL heterogeneous API, in form of SYCL kernels, which can be compiled targeting multi-core CPUs, GPGPUs, do following

```cpp
// accel_ascon_hasha.cpp
// see https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hasha.cpp

#include "accel_ascon.hpp"

int
main()
{
  sycl::default_selector s{};
  sycl::device d{ s };
  sycl::context c{ d };
  sycl::queue q{ c, d };

  // these many Ascon-HashA digests to be computed in-parallel
  constexpr size_t wi_cnt = 1024ul;
  // these many work-items to be grouped into single work-group
  constexpr size_t wg_size = 32ul;
  // each work-item will compute Ascon-HashA digest on 64 input bytes
  constexpr size_t per_wi_msg_len = 64ul;
  // each work-item will produce Ascon-HashA digest of 32 -bytes
  constexpr size_t per_wi_dig_len = 32ul;

  // total memory allocation for keeping input bytes ( for all work-items )
  constexpr size_t i_len = wi_cnt * per_wi_msg_len;
  // total memory allocation for keeping output digests ( for all work-items )
  constexpr size_t o_len = wi_cnt * per_wi_dig_len;

  uint8_t* msg = static_cast<uint8_t*>(sycl::malloc_shared(i_len, q));
  uint8_t* dig = static_cast<uint8_t*>(sycl::malloc_shared(o_len, q));

  using evt = sycl::event;
  using evts = std::vector<sycl::event>;

  // prepare random input bytes on host
  ascon_utils::random_data(msg, i_len);
  evt e0 = q.memset(dig, 0, o_len);

  // data-parallelly compute Ascon-HashA digests for `wi_cnt` -many independent,
  // non-overlapping input byte sequences & for each of them contiguously place
  // 32 digest bytes in respective memory locations
  evts e1{ e0 };
  evt e2 = accel_ascon::hash_a(q, msg, i_len, dig, o_len, wi_cnt, wg_size, e1);

  // host synchronization
  e2.wait();

  // sequentially rerun same computation on host to be sure that
  // data-parallel computation didn't end up computing some bytes wrong !
  for (size_t wi = 0; wi < wi_cnt; wi++) {
    uint8_t dig_[32];

    const size_t i_off = wi * per_wi_msg_len;
    const size_t o_off = wi * per_wi_dig_len;

    // compute Ascon-HashA digest on single text byte slice;
    // do it for `wi_cnt` -many times !
    ascon::hash_a(msg + i_off, per_wi_msg_len, dig_);

    // now do a byte-by-byte comparison !
    for (size_t b = 0; b < per_wi_dig_len; b++) {
      assert(dig_[b] == dig[o_off + b]);
    }
  }

  std::cout << "Accelerated Ascon-HashA works !" << std::endl;

  // deallocate acquired resources
  sycl::free(msg, q);
  sycl::free(dig, q);

  return EXIT_SUCCESS;
}
```

Compile & run it with

```bash
$ dpcpp -std=c++20 -fsycl -O3 -I ./include example/accel_ascon_hasha.cpp && ./a.out

Accelerated Ascon-HashA works !
```

For offloading SYCL kernels, implementing accelerated Ascon cryptographic suite, import `include/accel_ascon.hpp` & start using functions defined inside `accel_ascon::` namespace.

Find example of using all `accel_ascon::` namespaced SYCL kernels

- [Ascon-Hash SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hash.cpp)
- [Ascon-HashA SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/92f2c3e/example/accel_ascon_128a.cpp)
- [Ascon-80pq authenticated encryption/ verified decryption SYCL Kernel API](https://github.com/itzmeanjan/ascon/blob/7a2964f/example/accel_ascon_80pq.cpp)

---

### Wrapper Python API

For using `ascon` Python wrapper API, first you've to generate shared library object

```bash
make lib
file wrapper/libascon.so # okay to skip it
```

Now you can use Python interface

```bash
$ pushd wrapper/python
$ python3 # consider enabling `venv`

>>> import ascon
>>> msg = ascon.np.empty(0, dtype=ascon.np.uint8) # 0 -bytes message ( numpy byte array )
>>> ascon.hash(msg).tobytes().hex()               # computing ascon-hash digest
'7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91'
>>>

$ popd
```

Example script demonstrating usage of `ascon` Python API, can be found [here](https://github.com/itzmeanjan/ascon/blob/e3ead2b/wrapper/python/example.py)

```bash
make lib # must do !

pushd wrapper/python
python3 example.py
popd
```

> I suggest you read `ascon` Python API documentation [here](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/ascon.py).

> Going through Python API benchmark file should give you good overview of how to use `ascon`; follow [this](https://github.com/itzmeanjan/ascon/blob/92f218b/wrapper/python/test_ascon.py#L212-L343)

## Benchmark SYCL accelerated Ascon

I've written SYCL kernels which can be used for computing Ascon-Hash digest/ Ascon-HashA digest/ encrypted bytes & authentication tags using Ascon-128, Ascon-128a, Ascon-80pq/ decrypted text bytes & boolean verification flags using Ascon-128, Ascon-128a, Ascon-80pq, in data-parallel fashion on accelerator devices like multi-core CPUs, GPGPUs.

These kernels themselves are pretty simple as they import standard Ascon cryptographic suite ( read `ascon::` namespace ) and invoke N -many instances of relevant cryptographic routine on N -many independent, non-overlapping input byte slices producing N -many independent output bytes --- meaning N -many SYCL work-items are dispatched for some kernel ( say Ascon-Hash ) and without any in work-group communication/ synchronization N -many Ascon-Hash digests ( each 32 -bytes wide ) are computed & placed in respective memory locations, in contiguous fashion. These digests can now be transferred back to host & consumed for other purposes.

Similarly for Ascon-128 encryption algorithm, N -many independent, non-overlapping, equal length plain text slices are encrypted to N -many equal length cipher slices, also computing N -many authentication tags ( each 128 -bit wide ) while also using independent, non-overlapping secret keys ( N -many ), public message nonces ( N -many ) & associated data byte slices ( each slice of same length, total N -many ) as input to encryption algorithm. These encrypted message slices can now be data-parallelly decrypted by dispatching N -many SYCL work-items while each of these work-items to consume respective secret key ( 128 -bit ), public message nonce ( 128 -bit ), authentication tag ( 128 -bit ), ciphered byte slice & associated data byte slice, producing plain text bytes and boolean flag denoting verification status of decryption process.

Here I keep minimal benchmark results of SYCL kernels implementing following functionalities.

- [Ascon-Hash/ Ascon-HashA](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L110-L160)
- [Ascon-128 Encrypt/ Ascon-128a Encrypt](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L161-L298)
- [Ascon-128 Decrypt/ Ascon-128a Decrypt](https://github.com/itzmeanjan/ascon/blob/ee890f9/include/bench_utils.hpp#L299-L481)
- [Ascon-80pq Encrypt](https://github.com/itzmeanjan/ascon/blob/7a2964f/include/bench_utils.hpp#L489-L607)
- [Ascon-80pq Decrypt](https://github.com/itzmeanjan/ascon/blob/7a2964f/include/bench_utils.hpp#L608-L759)

Browse through results & respective build commands

- [Nvidia GPU](./results/gpu/nvidia.md)
- [Intel CPU](./results/cpu/intel.md)
- [Intel GPU](./results/gpu/intel.md)
