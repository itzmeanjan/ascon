#!/usr/bin/python3

import ascon
from random import randint, randbytes

H = 0xFFFF_FFFF_FFFF_FFFF
assert H == ((1 << 64) - 1)


def test_ascon_hash_kat():
    """
    This test case asserts Ascon Hash digests computed by my implementation
    against Known Answer Tests from Ascon NIST LWC submission package.
    """

    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes.fromhex(msg)
            md = bytes.fromhex(md)

            digest = ascon.hash(msg)

            check = md == digest
            assert check, f"[Ascon Hash KAT {cnt}] expected {md}, found {digest} !"

            # don't need this line, so discard
            fd.readline()


def test_ascon_hasha_kat():
    """
    This test case asserts Ascon HashA digests computed by my implementation
    against Known Answer Tests from Ascon NIST LWC submission package.
    """

    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes.fromhex(msg)
            md = bytes.fromhex(md)

            digest = ascon.hash_a(msg)

            check = md == digest
            assert check, f"[Ascon HashA KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()


def test_ascon_xof_kat():
    """
    This test case asserts Ascon XOF digests computed by my implementation
    against Known Answer Tests from Ascon NIST LWC submission package.
    """

    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes.fromhex(msg)
            md = bytes.fromhex(md)

            digest = ascon.xof(msg, 32)

            check = md == digest
            assert check, f"[Ascon XOF KAT {cnt}] expected {md}, found {digest} !"

            # don't need this line, so discard
            fd.readline()


def test_ascon_xofa_kat():
    """
    This test case asserts Ascon XOFA digests computed by my implementation
    against Known Answer Tests from Ascon NIST LWC submission package.
    """

    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes.fromhex(msg)
            md = bytes.fromhex(md)

            digest = ascon.xofa(msg, 32)

            check = md == digest
            assert check, f"[Ascon XOFA KAT {cnt}] expected {md}, found {digest} !"

            # don't need this line, so discard
            fd.readline()


def test_ascon_128_kat():
    """
    This test case asserts Ascon-128 encrypt/ decrypt implementation
    using Known Answer Tests as input; from Ascon NIST LWC submission package.
    """

    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
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

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            key = bytes.fromhex(key)
            nonce = bytes.fromhex(nonce)
            pt = bytes.fromhex(pt)
            ad = bytes.fromhex(ad)
            ct = bytes.fromhex(ct)

            cipher, tag = ascon.encrypt_128(key, nonce, ad, pt)
            flag, text = ascon.decrypt_128(key, nonce, ad, cipher, tag)

            check = (pt == text) and (ct == cipher + tag) and flag
            assert check, f"[Ascon-128 KAT {cnt}] expected {pt}, found {text} !"

            fd.readline()


def test_ascon_128a_kat():
    """
    This test case asserts Ascon-128a encrypt/ decrypt implementation
    using Known Answer Tests as input; from Ascon NIST LWC submission package.
    """

    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
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

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            key = bytes.fromhex(key)
            nonce = bytes.fromhex(nonce)
            pt = bytes.fromhex(pt)
            ad = bytes.fromhex(ad)
            ct = bytes.fromhex(ct)

            cipher, tag = ascon.encrypt_128a(key, nonce, ad, pt)
            flag, text = ascon.decrypt_128a(key, nonce, ad, cipher, tag)

            check = (pt == text) and (ct == cipher + tag) and flag
            assert check, f"[Ascon-128a KAT {cnt}] expected {pt}, found {text} !"

            fd.readline()


def test_ascon_80pq_kat():
    """
    This test case asserts Ascon-80pq encrypt/ decrypt implementation
    using Known Answer Tests as input; from Ascon NIST LWC submission package.
    """

    with open("LWC_AEAD_KAT_160_128.txt", "r") as fd:
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

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            key = bytes.fromhex(key)
            nonce = bytes.fromhex(nonce)
            pt = bytes.fromhex(pt)
            ad = bytes.fromhex(ad)
            ct = bytes.fromhex(ct)

            cipher, tag = ascon.encrypt_80pq(key, nonce, ad, pt)
            flag, text = ascon.decrypt_80pq(key, nonce, ad, cipher, tag)

            check = (pt == text) and (ct == cipher + tag) and flag
            assert check, f"[Ascon-80pq KAT {cnt}] expected {pt}, found {text} !"

            fd.readline()


def flip_bit(inp: bytes) -> bytes:
    """
    Randomly selects a byte offset of a given byte array ( inp ), whose single random bit
    will be flipped. Input is **not** mutated & single bit flipped byte array is returned back.

    Taken from https://github.com/itzmeanjan/elephant/blob/2a21c7e/wrapper/python/test_elephant.py#L217-L237
    """
    arr = bytearray(inp)
    ilen = len(arr)

    idx = randint(0, ilen - 1)
    bidx = randint(0, 7)

    mask0 = (0xFF << (bidx + 1)) & 0xFF
    mask1 = (0xFF >> (8 - bidx)) & 0xFF
    mask2 = 1 << bidx

    msb = arr[idx] & mask0
    lsb = arr[idx] & mask1
    bit = (arr[idx] & mask2) >> bidx

    arr[idx] = msb | ((1 - bit) << bidx) | lsb
    return bytes(arr)


def test_ascon_128_kat_auth_fail():
    """
    Test that Ascon128 authentication fails when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    DLEN = 32
    CTLEN = 32

    key = randbytes(16)
    nonce = randbytes(16)
    data = randbytes(DLEN)
    txt = randbytes(CTLEN)
    zeros = bytes(CTLEN)

    enc, tag = ascon.encrypt_128(key, nonce, data, txt)

    # case 0
    flg, dec = ascon.decrypt_128(key, nonce, flip_bit(data), enc, tag)

    assert not flg, "Ascon128 authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 1
    flg, dec = ascon.decrypt_128(key, nonce, data, flip_bit(enc), tag)

    assert not flg, "Ascon128 authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 2
    flg, dec = ascon.decrypt_128(key, nonce, flip_bit(data), flip_bit(enc), tag)

    assert not flg, "Ascon128 authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"


def test_ascon_128a_kat_auth_fail():
    """
    Test that Ascon128a authentication fails when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    DLEN = 32
    CTLEN = 32

    key = randbytes(16)
    nonce = randbytes(16)
    data = randbytes(DLEN)
    txt = randbytes(CTLEN)
    zeros = bytes(CTLEN)

    enc, tag = ascon.encrypt_128a(key, nonce, data, txt)

    # case 0
    flg, dec = ascon.decrypt_128a(key, nonce, flip_bit(data), enc, tag)

    assert not flg, "Ascon128a authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 1
    flg, dec = ascon.decrypt_128a(key, nonce, data, flip_bit(enc), tag)

    assert not flg, "Ascon128a authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 2
    flg, dec = ascon.decrypt_128a(key, nonce, flip_bit(data), flip_bit(enc), tag)

    assert not flg, "Ascon128a authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"


def test_ascon_80pq_kat_auth_fail():
    """
    Test that Ascon80pq authentication fails when random bit of associated data
    and/ or encrypted text are flipped. Also it's ensured that in case of authentication
    failure unverified plain text is never released, instead memory allocation for
    decrypted plain text is zeroed.
    """
    DLEN = 32
    CTLEN = 32

    key = randbytes(20)
    nonce = randbytes(16)
    data = randbytes(DLEN)
    txt = randbytes(CTLEN)
    zeros = bytes(CTLEN)

    enc, tag = ascon.encrypt_80pq(key, nonce, data, txt)

    # case 0
    flg, dec = ascon.decrypt_80pq(key, nonce, flip_bit(data), enc, tag)

    assert not flg, "Ascon80pq authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 1
    flg, dec = ascon.decrypt_80pq(key, nonce, data, flip_bit(enc), tag)

    assert not flg, "Ascon80pq authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"

    # case 2
    flg, dec = ascon.decrypt_80pq(key, nonce, flip_bit(data), flip_bit(enc), tag)

    assert not flg, "Ascon80pq authentication must fail !"
    assert zeros == dec, "Unverified plain text must not be released !"


if __name__ == "__main__":
    print(f"Use `pytest` for running test cases/ benchmarks !")
