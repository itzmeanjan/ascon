#!/usr/bin/python3

"""
  Before using `ascon` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then function calls are forwarded to respective DPC++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>

  Project: https://github.com/itzmeanjan/ascon
"""

import ctypes as ct
from genericpath import exists
from posixpath import abspath
from typing import Tuple
import numpy as np

SO_PATH: str = abspath("../libascon.so")
assert exists(SO_PATH), "`make lib` to generate shared library !"

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

len_t = ct.c_size_t
bytes_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags="CONTIGUOUS")


def hash(msg: np.ndarray) -> np.ndarray:
    """
    Computes 256 -bit Ascon Hash of arbitrary length input byte array;
    see section 2.5 of Ascon specification
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input : numpy ndarray of data type `uint8` | len >= 0
    Output: numpy ndarray of data type `uint8` | len = 32
    """
    # ensure that `msg` is a numpy ndarray of unsigned characters ( uint8_t )
    assert np.uint8().dtype == msg.dtype, "expected numpy ndarray[u8] as input"

    # allocate memory for storing 256 -bit Ascon digest
    digest = np.empty(32, dtype=np.uint8)

    SO_LIB.hash.argtypes = [bytes_t, len_t, bytes_t]
    SO_LIB.hash(msg, msg.size, digest)

    # return 32 -bytes Ascon digest back
    return digest


def hash_a(msg: np.ndarray) -> np.ndarray:
    """
    Computes 256 -bit Ascon HashA of arbitrary length input byte array;
    see section 2.5 of Ascon specification
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input : numpy ndarray of data type `uint8` | len >= 0
    Output: numpy ndarray of data type `uint8` | len = 32
    """
    # ensure that `msg` is a numpy ndarray of unsigned characters ( uint8_t )
    assert np.uint8().dtype == msg.dtype, "expected numpy ndarray[u8] as input"

    # allocate memory for storing 256 -bit Ascon digest
    digest = np.empty(32, dtype=np.uint8)

    SO_LIB.hash_a.argtypes = [bytes_t, len_t, bytes_t]
    SO_LIB.hash_a(msg, msg.size, digest)

    # return 32 -bytes Ascon digest back
    return digest


def encrypt_128(
    key: bytes, nonce: bytes, data: np.ndarray, text: np.ndarray
) -> Tuple[np.ndarray, bytes]:
    """
    Encrypts plain text using Ascon-128 authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit tag; see algorithm 1 in
    Ascon specification https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 128 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) plain text ( numpy ndarray of data type `uint8` )
    Output:
        - arbitrary length ( = len(text) ) encrypted data ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == text.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    t_len = text.size  # >= 0 bytes
    cipher = np.empty(t_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    args = [ct.c_char_p, ct.c_char_p, bytes_t, len_t, bytes_t, len_t, bytes_t, bytes_t]
    SO_LIB.encrypt_128.argtypes = args
    SO_LIB.encrypt_128(key, nonce, data, d_len, text, t_len, cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher, tag.tobytes()


def decrypt_128(
    key: bytes, nonce: bytes, data: np.ndarray, cipher: np.ndarray, tag: bytes
) -> Tuple[bool, np.ndarray]:
    """
    Decrypts ciphered text using Ascon-128 verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 128 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) ciphered text ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    Output:
        - status of successful decryption
        - arbitrary length ( = len(cipher) ) decrypted plain text ( numpy ndarray of data type `uint8` )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == cipher.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    c_len = cipher.size  # >= 0 bytes
    text = np.empty(c_len, dtype=u8)  # allocate memory for keeping plain text

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        ct.c_char_p,
        ct.c_char_p,
        bytes_t,
        len_t,
        bytes_t,
        len_t,
        bytes_t,
        ct.c_char_p,
    ]
    SO_LIB.decrypt_128.restype = ct.c_bool
    SO_LIB.decrypt_128.argtypes = args
    v = SO_LIB.decrypt_128(key, nonce, data, d_len, cipher, c_len, text, tag)

    # return decryption status, decrypted plain text
    return v, text


def encrypt_128a(
    key: bytes, nonce: bytes, data: np.ndarray, text: np.ndarray
) -> Tuple[np.ndarray, bytes]:
    """
    Encrypts plain text using Ascon-128a authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit tag; see algorithm 1 in
    Ascon specification https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 128 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) plain text ( numpy ndarray of data type `uint8` )
    Output:
        - arbitrary length ( = len(text) ) encrypted data ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == text.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    t_len = text.size  # >= 0 bytes
    cipher = np.empty(t_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    args = [ct.c_char_p, ct.c_char_p, bytes_t, len_t, bytes_t, len_t, bytes_t, bytes_t]
    SO_LIB.encrypt_128a.argtypes = args
    SO_LIB.encrypt_128a(key, nonce, data, d_len, text, t_len, cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher, tag.tobytes()


def decrypt_128a(
    key: bytes, nonce: bytes, data: np.ndarray, cipher: np.ndarray, tag: bytes
) -> Tuple[bool, np.ndarray]:
    """
    Decrypts ciphered text using Ascon-128a verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 128 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) ciphered text ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    Output:
        - status of successful decryption
        - arbitrary length ( = len(cipher) ) decrypted plain text ( numpy ndarray of data type `uint8` )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == cipher.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    c_len = cipher.size  # >= 0 bytes
    text = np.empty(c_len, dtype=u8)  # allocate memory for keeping plain text

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        ct.c_char_p,
        ct.c_char_p,
        bytes_t,
        len_t,
        bytes_t,
        len_t,
        bytes_t,
        ct.c_char_p,
    ]
    SO_LIB.decrypt_128a.restype = ct.c_bool
    SO_LIB.decrypt_128a.argtypes = args
    v = SO_LIB.decrypt_128a(key, nonce, data, d_len, cipher, c_len, text, tag)

    # return decryption status, decrypted plain text
    return v, text


def encrypt_80pq(
    key: bytes, nonce: bytes, data: np.ndarray, text: np.ndarray
) -> Tuple[np.ndarray, bytes]:
    """
    Encrypts plain text using Ascon-80pq authenticated encryption algorithm, producing
    encrypted text of length same as input plain text and 128 -bit authentication tag; see algorithm 1 in
    Ascon specification https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 160 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) plain text ( numpy ndarray of data type `uint8` )
    Output:
        - arbitrary length ( = len(text) ) encrypted data ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == text.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    t_len = text.size  # >= 0 bytes
    cipher = np.empty(t_len, dtype=u8)
    tag = np.empty(16, dtype=u8)

    assert len(key) == 20  # 160 -bit secret key
    assert len(nonce) == 16  # 128 -bit public message nonce

    args = [ct.c_char_p, ct.c_char_p, bytes_t, len_t, bytes_t, len_t, bytes_t, bytes_t]
    SO_LIB.encrypt_80pq.argtypes = args
    SO_LIB.encrypt_80pq(key, nonce, data, d_len, text, t_len, cipher, tag)

    # return cipher text, tag ( 128 -bit )
    return cipher, tag.tobytes()


def decrypt_80pq(
    key: bytes, nonce: bytes, data: np.ndarray, cipher: np.ndarray, tag: bytes
) -> Tuple[bool, np.ndarray]:
    """
    Decrypts ciphered text using Ascon-80pq verified decryption algorithm, producing
    plain text of length same as input ciphered text and boolean flag denoting
    status of successful decryption; see algorithm 1 in Ascon specification
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input :
        - 160 -bit secret key ( as bytes )
        - 128 -bit nonce ( as bytes )
        - arbitrary length ( >= 0 ) associated data ( numpy ndarray of data type `uint8` )
        - arbitrary length ( >= 0 ) ciphered text ( numpy ndarray of data type `uint8` )
        - 128 -bit tag ( as bytes )
    Output:
        - status of successful decryption
        - arbitrary length ( = len(cipher) ) decrypted plain text ( numpy ndarray of data type `uint8` )
    """
    u8 = np.uint8

    assert u8().dtype == data.dtype, "expected numpy ndarray[u8] as input"
    assert u8().dtype == cipher.dtype, "expected numpy ndarray[u8] as input"

    d_len = data.size  # >= 0 bytes
    c_len = cipher.size  # >= 0 bytes
    text = np.empty(c_len, dtype=u8)  # allocate memory for keeping plain text

    assert len(key) == 20  # 160 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    args = [
        ct.c_char_p,
        ct.c_char_p,
        bytes_t,
        len_t,
        bytes_t,
        len_t,
        bytes_t,
        ct.c_char_p,
    ]
    SO_LIB.decrypt_80pq.restype = ct.c_bool
    SO_LIB.decrypt_80pq.argtypes = args
    v = SO_LIB.decrypt_80pq(key, nonce, data, d_len, cipher, c_len, text, tag)

    # return decryption status, decrypted plain text
    return v, text


if __name__ == "__main__":
    print("Use `ascon` as library module !")
