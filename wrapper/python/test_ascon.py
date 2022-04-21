#!/usr/bin/python3

import ascon
import numpy as np

# = (1 << 64) - 1
H = 0xffff_ffff_ffff_ffff


def test_hash_kat():
    '''
    This test case asserts Ascon Hash digests computed by my implementation
    against Known Answer Tests generated by 
    https://github.com/meichlseder/pyascon/blob/236aadd9e09f40bc57064eba7cbade6f46a4c532/genkat.py
    '''

    count = 0  # -many KATs to be run

    with open('LWC_HASH_KAT_256.txt', 'r') as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split('=')][-1])
            msg = [i.strip() for i in msg.split('=')][-1]
            md = [i.strip() for i in md.split('=')][-1]

            # convert input message to numpy ndarray of uint8_t
            msg = np.asarray([int(f'0x{msg[(i << 1): ((i+1) << 1)]}', base=16)
                              for i in range(len(msg) >> 1)], dtype=np.uint8)

            # convert output digest to numpy ndarray of uint8_t
            md = np.asarray([int(f'0x{md[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(md) >> 1)], dtype=np.uint8)

            # compute Ascon Hash using my implementation
            digest = ascon.hash(msg)
            # check 32 -bytes element-wise
            check = (md == digest).all()

            assert check, f'[Ascon Hash KAT {cnt}] expected {md}, found {digest} !'

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f'[test] passed {count} -many Ascon Hash KAT(s)')


def test_hashA_kat():
    '''
    This test case asserts Ascon HashA digests computed by my implementation
    against Known Answer Tests generated by 
    https://github.com/meichlseder/pyascon/blob/236aadd9e09f40bc57064eba7cbade6f46a4c532/genkat.py
    '''

    count = 0  # -many KATs to be run

    with open('LWC_HASH_KAT_256.txt', 'r') as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split('=')][-1])
            msg = [i.strip() for i in msg.split('=')][-1]
            md = [i.strip() for i in md.split('=')][-1]

            # convert input message to numpy ndarray of uint8_t
            msg = np.asarray([int(f'0x{msg[(i << 1): ((i+1) << 1)]}', base=16)
                              for i in range(len(msg) >> 1)], dtype=np.uint8)

            # convert output digest to numpy ndarray of uint8_t
            md = np.asarray([int(f'0x{md[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(md) >> 1)], dtype=np.uint8)

            # compute Ascon HashA using my implementation
            digest = ascon.hash_a(msg)
            # check 32 -bytes element-wise
            check = (md == digest).all()

            assert check, f'[Ascon Hash KAT {cnt}] expected {md}, found {digest} !'

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f'[test] passed {count} -many Ascon HashA KAT(s)')


def test_ascon_128_kat():
    '''
    This test case asserts Ascon-128 encrypt/ decrypt implementation
    using Known Answer Tests as input; generated by 
    https://github.com/meichlseder/pyascon/blob/236aadd9e09f40bc57064eba7cbade6f46a4c532/genkat.py
    '''

    count = 0  # -many KATs to be run

    with open('LWC_AEAD_KAT_128_128.txt', 'r') as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split('=')][-1])
            key = [i.strip() for i in key.split('=')][-1]
            nonce = [i.strip() for i in nonce.split('=')][-1]
            pt = [i.strip() for i in pt.split('=')][-1]
            ad = [i.strip() for i in ad.split('=')][-1]

            # 128 -bit secret key
            key = int(f'0x{key}', base=16).to_bytes(16, 'big')
            # 128 -bit nonce
            nonce = int(f'0x{nonce}', base=16).to_bytes(16, 'big')
            # plain text
            pt = np.asarray([int(f'0x{pt[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(pt) >> 1)], dtype=np.uint8)
            # associated data
            ad = np.asarray([int(f'0x{ad[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(ad) >> 1)], dtype=np.uint8)

            cipher, tag = ascon.encrypt_128(key, nonce, ad, pt)
            flag, text = ascon.decrypt_128(key, nonce, ad, cipher, tag)

            check = (pt == text).all()
            assert check and flag, f'[Ascon-128 KAT {cnt}] expected {pt}, found {text} !'

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f'[test] passed {count} -many Ascon-128 KAT(s)')


def test_ascon_128a_kat():
    '''
    This test case asserts Ascon-128a encrypt/ decrypt implementation
    using Known Answer Tests as input; generated by
    https://github.com/meichlseder/pyascon/blob/236aadd9e09f40bc57064eba7cbade6f46a4c532/genkat.py
    '''

    count = 0  # -many KATs to be run

    with open('LWC_AEAD_KAT_128_128.txt', 'r') as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split('=')][-1])
            key = [i.strip() for i in key.split('=')][-1]
            nonce = [i.strip() for i in nonce.split('=')][-1]
            pt = [i.strip() for i in pt.split('=')][-1]
            ad = [i.strip() for i in ad.split('=')][-1]

            # 128 -bit secret key
            key = int(f'0x{key}', base=16).to_bytes(16, 'big')
            # 128 -bit nonce
            nonce = int(f'0x{nonce}', base=16).to_bytes(16, 'big')
            # plain text
            pt = np.asarray([int(f'0x{pt[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(pt) >> 1)], dtype=np.uint8)
            # associated data
            ad = np.asarray([int(f'0x{ad[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(ad) >> 1)], dtype=np.uint8)

            cipher, tag = ascon.encrypt_128a(key, nonce, ad, pt)
            flag, text = ascon.decrypt_128a(key, nonce, ad, cipher, tag)

            check = (pt == text).all()
            assert check and flag, f'[Ascon-128a KAT {cnt}] expected {pt}, found {text} !'

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f'[test] passed {count} -many Ascon-128a KAT(s)')


def test_ascon_80pq_kat():
    '''
    This test case asserts Ascon-80pq encrypt/ decrypt implementation
    using Known Answer Tests as input; generated by 
    https://github.com/meichlseder/pyascon/blob/236aadd9e09f40bc57064eba7cbade6f46a4c532/genkat.py
    '''

    count = 0  # -many KATs to be run

    with open('LWC_AEAD_KAT_160_128.txt', 'r') as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split('=')][-1])
            key = [i.strip() for i in key.split('=')][-1]
            nonce = [i.strip() for i in nonce.split('=')][-1]
            pt = [i.strip() for i in pt.split('=')][-1]
            ad = [i.strip() for i in ad.split('=')][-1]

            # 160 -bit secret key
            key = int(f'0x{key}', base=16).to_bytes(20, 'big')
            # 128 -bit nonce
            nonce = int(f'0x{nonce}', base=16).to_bytes(16, 'big')
            # plain text
            pt = np.asarray([int(f'0x{pt[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(pt) >> 1)], dtype=np.uint8)
            # associated data
            ad = np.asarray([int(f'0x{ad[(i << 1): ((i+1) << 1)]}', base=16)
                             for i in range(len(ad) >> 1)], dtype=np.uint8)

            cipher, tag = ascon.encrypt_80pq(key, nonce, ad, pt)
            flag, text = ascon.decrypt_80pq(key, nonce, ad, cipher, tag)

            check = (pt == text).all()
            assert check and flag, f'[Ascon-80pq KAT {cnt}] expected {pt}, found {text} !'

            # don't need this line, so discard
            fd.readline()
            # to keep track of how many KATs executed !
            count = cnt

    print(f'[test] passed {count} -many Ascon-80pq KAT(s)')


def test_bench_ascon_hash(benchmark):
    '''
    Benchmark Ascon-Hash implementation with random 64 -bytes input
    '''

    # prepare random 64 -bytes input
    msg = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    @benchmark
    def compute():
        return ascon.hash(msg)


def test_bench_ascon_hasha(benchmark):
    '''
    Benchmark Ascon-HashA implementation with random 64 -bytes input
    '''

    # prepare random 64 -bytes input
    msg = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    @benchmark
    def compute():
        return ascon.hash_a(msg)


def test_bench_ascon_128_encrypt(benchmark):
    '''
    Benchmark Ascon-128 authenticated encryption implementation with
    random 64 -bytes associated data & 64 -bytes plain text
    '''

    # random 128 -bit secret key
    key = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    @benchmark
    def compute():
        return ascon.encrypt_128(key, nonce, data, text)

    # ensure encryption works as expected !
    enc, tag = compute
    flag, _ = ascon.decrypt_128(key, nonce, data, enc, tag)

    assert flag


def test_bench_ascon_128_decrypt(benchmark):
    '''
    Benchmark Ascon-128 verified decryption implementation with
    random 64 -bytes associated data & 64 -bytes cipher text
    '''

    # random 128 -bit secret key
    key = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    # encrypt text
    enc, tag = ascon.encrypt_128(key, nonce, data, text)

    @benchmark
    def compute():
        return ascon.decrypt_128(key, nonce, data, enc, tag)

    # ensure decryption works as expected !
    flag, _ = compute

    assert flag


def test_bench_ascon_128a_encrypt(benchmark):
    '''
    Benchmark Ascon-128a authenticated encryption implementation with
    random 64 -bytes associated data & 64 -bytes plain text
    '''

    # random 128 -bit secret key
    key = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    @benchmark
    def compute():
        return ascon.encrypt_128a(key, nonce, data, text)

    # ensure encryption works as expected !
    enc, tag = compute
    flag, _ = ascon.decrypt_128a(key, nonce, data, enc, tag)

    assert flag


def test_bench_ascon_128a_decrypt(benchmark):
    '''
    Benchmark Ascon-128a verified decryption implementation with
    random 64 -bytes associated data & 64 -bytes cipher text
    '''

    # random 128 -bit secret key
    key = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    # encrypt text
    enc, tag = ascon.encrypt_128a(key, nonce, data, text)

    @benchmark
    def compute():
        return ascon.decrypt_128a(key, nonce, data, enc, tag)

    # ensure decryption works as expected !
    flag, _ = compute

    assert flag


def test_bench_ascon_80pq_encrypt(benchmark):
    '''
    Benchmark Ascon-80pq authenticated encryption implementation with
    random 64 -bytes associated data & 64 -bytes plain text
    '''

    # random 160 -bit secret key
    key = np.random.randint(0, high=H, size=3, dtype=np.uint64).tobytes()[:20]
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    @benchmark
    def compute():
        return ascon.encrypt_80pq(key, nonce, data, text)

    # ensure encryption works as expected !
    enc, tag = compute
    flag, _ = ascon.decrypt_80pq(key, nonce, data, enc, tag)

    assert flag


def test_bench_ascon_80pq_decrypt(benchmark):
    '''
    Benchmark Ascon-80pq verified decryption implementation with
    random 64 -bytes associated data & 64 -bytes cipher text
    '''

    # random 160 -bit secret key
    key = np.random.randint(0, high=H, size=3, dtype=np.uint64).tobytes()[:20]
    # random 128 -bit nonce
    nonce = np.random.randint(0, high=H, size=2, dtype=np.uint64).tobytes()
    # random 64 -bytes associated data
    data = np.random.randint(0, high=256, size=64, dtype=np.uint8)
    # random 64 -bytes plain text
    text = np.random.randint(0, high=256, size=64, dtype=np.uint8)

    # encrypt text
    enc, tag = ascon.encrypt_80pq(key, nonce, data, text)

    @benchmark
    def compute():
        return ascon.decrypt_80pq(key, nonce, data, enc, tag)

    # ensure decryption works as expected !
    flag, _ = compute

    assert flag


if __name__ == '__main__':
    print(f'Use `pytest` for running test cases/ benchmarks !')
