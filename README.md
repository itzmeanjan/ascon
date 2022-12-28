# ascon
Accelerated Ascon: Light Weight Cryptography

## Overview

`ascon` is the very first cryptographic suite I've decided to implement from the list of algorithms competing in the final round of NIST **L**ight **W**eight **C**ryptography competition. I suggest you follow [this](https://csrc.nist.gov/Projects/Lightweight-Cryptography). Here I keep a zero-dependency, C++ header-only library implementation of `ascon` LWC suite, which should be easy to use; find examples below. Following functions are implemented

- Ascon-128 authenticated encryption/ verified decryption ( AEAD )
- Ascon-128a authenticated encryption/ verified decryption ( AEAD )
- Ascon-80pq authenticated encryption/ verified decryption ( AEAD )
- Ascon-Hash
- Ascon-HashA

> Read more about AEAD [here](https://en.wikipedia.org/wiki/Authenticated_encryption).

> I've followed Ascon [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf) for this work.

This implementation doesn't depend on anything else, except C++ standard library ( which implements C++20 specification ). I've also written Python wrapper interface to C++ implementation using `ctypes`, which is used for testing functional correctness using Known Answer Tests, provided with NIST LWC submission package of `ascon`. Benchmarking `ascon` makes use of `google-benchmark` library; see below.

## Prerequisites

- Make sure you've C++ compiler `g++`/ `clang++` installed, along with C++20 standard library

```bash
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0

$ clang++ --version
Ubuntu clang version 14.0.0-1ubuntu1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin
```

- System development utilities like `make`, `cmake` will be required for ease of building library/ testing/ benchmarking

```bash
$ make -v
GNU Make 4.3

$ cmake  --version
cmake version 3.22.1
```

- You'll need `python3`, if you want to explore ( test/ benchmark/ use ) `ascon` Python wrapper API

```bash
$ python3 --version
Python 3.10.6
```

- You'll also need to install Python dependencies like

```bash
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- Actually it's better idea to use `venv` to keep this project isolated from existing system environment

```bash
# make sure you've `venv`
# see https://pypi.org/project/virtualenv
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

For ensuring that Ascon is implemented correctly and it's conformant with the specification ( linked above )

- Ensure functional correctness of Ascon permutation, along with correctness of AEAD routines i.e. $\{{encrypt(), decrypt()}\}$
- Assess whether this implementation of Ascon is conformant using **K**nown **A**nswer **T**ests, provided with NIST submission of Ascon

```bash
make             # test_ascon + test_kat

make test_ascon  # only functional correctness
make test_kat    # conformance with KATs ( needs Python )
```

## Benchmarking

Find micro-benchmarking ( using `google-benchmark` ) results [here](./bench/README.md).

## Usage

### C++ API

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
$ g++ -Wall -std=c++20 -O3 -I./include example/ascon_hash.cpp && ./a.out

Ascon-Hash digest :     2eb89744de7f9a6f47d53db756bb2f67b127da96762a1c47a5d7bfc1f7273f5c
```

See example of using

- [Ascon-Hash API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hash.cpp)
- [Ascon-HashA API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_hasha.cpp)
- [Ascon-128 authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128.cpp)
- [Ascon-128a authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/92f218b/example/ascon_128a.cpp)
- [Ascon-80pq authenticated encryption/ verified decryption API](https://github.com/itzmeanjan/ascon/blob/b680d4b/example/ascon_80pq.cpp)

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
