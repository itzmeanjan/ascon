#!/usr/bin/python3

"""
  Before using `ascon` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then function calls are forwarded to respective DPC++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>

  Project: https://github.com/itzmeanjan/ascon
"""

from ctypes import CDLL, c_size_t, c_char_p, c_bool, create_string_buffer
from genericpath import exists
from posixpath import abspath
from typing import Tuple

SO_PATH: str = abspath("../libascon.so")
assert exists(SO_PATH), "`make lib` to generate shared library !"

SO_LIB: CDLL = CDLL(SO_PATH)


def hash(msg: bytes) -> bytes:
    """
    Computes 256 -bit Ascon Hash of arbitrary length input byte array;
    see section 2.5 of Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    digest = create_string_buffer(32)

    SO_LIB.hash.argtypes = [c_char_p, c_size_t, c_char_p]
    SO_LIB.hash(msg, len(msg), digest)

    return digest.raw


def hash_a(msg: bytes) -> bytes:
    """
    Computes 256 -bit Ascon HashA of arbitrary length input byte array;
    see section 2.5 of Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    digest = create_string_buffer(32)

    SO_LIB.hash_a.argtypes = [c_char_p, c_size_t, c_char_p]
    SO_LIB.hash_a(msg, len(msg), digest)

    return digest.raw


def xof(msg: bytes, olen: int) -> bytes:
    """
    Computes olen -bytes Ascon XOF of arbitrary length input byte array;
    see section 2.5 of Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    digest = create_string_buffer(olen)

    SO_LIB.xof.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t]
    SO_LIB.xof(msg, len(msg), digest, olen)

    return digest.raw


def encrypt_128(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts plain text using Ascon-128 authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit tag; see algorithm 1 in
    Ascon specification https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    cipher = create_string_buffer(len(text))
    tag = create_string_buffer(16)

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.encrypt_128.argtypes = args
    SO_LIB.encrypt_128(key, nonce, data, len(data), text, len(text), cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher.raw, tag.raw


def decrypt_128(
    key: bytes, nonce: bytes, data: bytes, cipher: bytes, tag: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts ciphered text using Ascon-128 verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    text = create_string_buffer(len(cipher))

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.decrypt_128.restype = c_bool
    SO_LIB.decrypt_128.argtypes = args
    v = SO_LIB.decrypt_128(key, nonce, data, len(data), cipher, len(cipher), text, tag)

    # return decryption status, decrypted plain text
    return v, text.raw


def encrypt_128a(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts plain text using Ascon-128a authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit tag; see algorithm 1 in
    Ascon specification https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    cipher = create_string_buffer(len(text))
    tag = create_string_buffer(16)

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.encrypt_128a.argtypes = args
    SO_LIB.encrypt_128a(key, nonce, data, len(data), text, len(text), cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher.raw, tag.raw


def decrypt_128a(
    key: bytes, nonce: bytes, data: bytes, cipher: bytes, tag: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts ciphered text using Ascon-128a verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    text = create_string_buffer(len(cipher))

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.decrypt_128a.restype = c_bool
    SO_LIB.decrypt_128a.argtypes = args
    v = SO_LIB.decrypt_128a(key, nonce, data, len(data), cipher, len(cipher), text, tag)

    # return decryption status, decrypted plain text
    return v, text.raw


def encrypt_80pq(
    key: bytes, nonce: bytes, data: bytes, text: bytes
) -> Tuple[bytes, bytes]:
    """
    Encrypts plain text using Ascon-80pq authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit authentication tag; see algorithm 1 in
    Ascon specification https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    cipher = create_string_buffer(len(text))
    tag = create_string_buffer(16)

    assert len(key) == 20  # 160 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.encrypt_80pq.argtypes = args
    SO_LIB.encrypt_80pq(key, nonce, data, len(data), text, len(text), cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher.raw, tag.raw


def decrypt_80pq(
    key: bytes, nonce: bytes, data: bytes, cipher: bytes, tag: bytes
) -> Tuple[bool, bytes]:
    """
    Decrypts ciphered text using Ascon-80pq verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf
    """
    text = create_string_buffer(len(cipher))

    assert len(key) == 20  # 160 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_size_t,
        c_char_p,
        c_size_t,
        c_char_p,
        c_char_p,
    ]
    SO_LIB.decrypt_80pq.restype = c_bool
    SO_LIB.decrypt_80pq.argtypes = args
    v = SO_LIB.decrypt_80pq(key, nonce, data, len(data), cipher, len(cipher), text, tag)

    # return decryption status, decrypted plain text
    return v, text.raw


if __name__ == "__main__":
    print("Use `ascon` as library module !")
