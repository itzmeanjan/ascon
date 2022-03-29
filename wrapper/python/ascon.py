#!/usr/bin/python3

'''
  Before using `ascon` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then function calls are forwarded to respective DPC++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  Project: https://github.com/itzmeanjan/ascon
'''

import ctypes as ct
from genericpath import exists
from posixpath import abspath
from typing import Tuple
import numpy as np

SO_PATH: str = abspath('../libascon.so')
assert exists(SO_PATH), '`make lib` to generate shared library !'

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)


class secret_key_t(ct.Structure):
    '''
    128 -bit Ascon secret key; see table 1 of Ascon specification 
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
    '''
    _fields_ = [('limbs', ct.c_uint64 * 2)]  # uint64_t[2]


class nonce_t(ct.Structure):
    '''
    128 -bit Ascon nonce; see table 1 of Ascon specification 
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
    '''
    _fields_ = [('limbs', ct.c_uint64 * 2)]  # uint64_t[2]


class tag_t(ct.Structure):
    '''
    128 -bit Ascon tag; see table 1 of Ascon specification 
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
    '''
    _fields_ = [('limbs', ct.c_uint64 * 2)]  # uint64_t[2]


# setting proper data type for function arguments
len_t = ct.c_size_t

msg_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags='CONTIGUOUS')
digest_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags='CONTIGUOUS')

data_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags='CONTIGUOUS')
text_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags='CONTIGUOUS')
cipher_t = np.ctypeslib.ndpointer(dtype=np.uint8, ndim=1, flags='CONTIGUOUS')

secret_key_tp = ct.POINTER(secret_key_t)
nonce_tp = ct.POINTER(nonce_t)
tag_tp = ct.POINTER(tag_t)


def hash(msg: np.ndarray) -> np.ndarray:
    '''
    Computes 256 -bit Ascon Hash of arbitrary length input byte array; 
    see section 2.5 of Ascon specification 
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input : numpy ndarray of data type `uint8` | len >= 0
    Output: numpy ndarray of data type `uint8` | len = 32
    '''
    # ensure that `msg` is a numpy ndarray of unsigned characters ( uint8_t )
    assert np.uint8().dtype == msg.dtype, 'expected numpy ndarray[u8] as input'

    # allocate memory for storing 256 -bit Ascon digest
    digest = np.empty(32, dtype=np.uint8)

    SO_LIB.hash.argtypes = [msg_t, len_t, digest_t]
    SO_LIB.hash(msg, msg.size, digest)

    # return 32 -bytes Ascon digest back
    return digest


def hash_a(msg: np.ndarray) -> np.ndarray:
    '''
    Computes 256 -bit Ascon HashA of arbitrary length input byte array; 
    see section 2.5 of Ascon specification 
    https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

    Input : numpy ndarray of data type `uint8` | len >= 0
    Output: numpy ndarray of data type `uint8` | len = 32
    '''
    # ensure that `msg` is a numpy ndarray of unsigned characters ( uint8_t )
    assert np.uint8().dtype == msg.dtype, 'expected numpy ndarray[u8] as input'

    # allocate memory for storing 256 -bit Ascon digest
    digest = np.empty(32, dtype=np.uint8)

    SO_LIB.hash_a.argtypes = [msg_t, len_t, digest_t]
    SO_LIB.hash_a(msg, msg.size, digest)

    # return 32 -bytes Ascon digest back
    return digest


def encrypt_128(key: bytes, nonce: bytes, data: np.ndarray, text: np.ndarray) -> Tuple[np.ndarray, bytes]:
    '''
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
    '''
    u8 = np.uint8

    assert u8().dtype == data.dtype, 'expected numpy ndarray[u8] as input'
    assert u8().dtype == text.dtype, 'expected numpy ndarray[u8] as input'

    d_len = data.size  # >= 0 bytes
    t_len = text.size  # >= 0 bytes
    cipher = np.empty(t_len, dtype=u8)  # allocate memory for keeping cipher

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    l0 = int.from_bytes(key[:8], 'big', signed=False)
    l1 = int.from_bytes(key[8:], 'big', signed=False)

    key_ = secret_key_t(limbs=(l0, l1))
    key_ = ct.byref(key_)

    l0 = int.from_bytes(nonce[:8], 'big', signed=False)
    l1 = int.from_bytes(nonce[8:], 'big', signed=False)

    nonce_ = nonce_t(limbs=(l0, l1))
    nonce_ = ct.byref(nonce_)

    args = [secret_key_tp, nonce_tp, data_t, len_t, text_t, len_t, cipher_t]

    # set function return type
    SO_LIB.encrypt_128.restype = tag_t
    # set function signature
    SO_LIB.encrypt_128.argtypes = args

    # encrypt using Ascon-128
    tag = SO_LIB.encrypt_128(key_, nonce_, data, d_len, text, t_len, cipher)

    # converting tag to byte array
    tag_ = tag.limbs[0].to_bytes(8, 'big') + tag.limbs[1].to_bytes(8, 'big')

    # return cipher text, tag ( 128 -bit )
    return cipher, tag_


def decrypt_128(key: bytes, nonce: bytes, data: np.ndarray, cipher: np.ndarray, tag: bytes) -> Tuple[bool, np.ndarray]:
    '''
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
    '''
    u8 = np.uint8

    assert u8().dtype == data.dtype, 'expected numpy ndarray[u8] as input'
    assert u8().dtype == cipher.dtype, 'expected numpy ndarray[u8] as input'

    d_len = data.size  # >= 0 bytes
    c_len = cipher.size  # >= 0 bytes
    text = np.empty(c_len, dtype=u8)  # allocate memory for keeping plain text

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    l0 = int.from_bytes(key[:8], 'big', signed=False)
    l1 = int.from_bytes(key[8:], 'big', signed=False)

    key_ = secret_key_t(limbs=(l0, l1))
    key_ = ct.byref(key_)

    l0 = int.from_bytes(nonce[:8], 'big', signed=False)
    l1 = int.from_bytes(nonce[8:], 'big', signed=False)

    nonce_ = nonce_t(limbs=(l0, l1))
    nonce_ = ct.byref(nonce_)

    l0 = int.from_bytes(tag[:8], 'big', signed=False)
    l1 = int.from_bytes(tag[8:], 'big', signed=False)

    tag_ = tag_t(limbs=(l0, l1))
    tag_ = ct.byref(tag_)

    args = [secret_key_tp, nonce_tp, data_t,
            len_t, cipher_t, len_t, text_t, tag_tp]

    # set function return type
    SO_LIB.decrypt_128.restype = ct.c_bool
    # set function signature
    SO_LIB.decrypt_128.argtypes = args

    # decrypt using Ascon-128
    v = SO_LIB.decrypt_128(key_, nonce_, data, d_len,
                           cipher, c_len, text, tag_)

    assert v, 'tag doesn\'t match, failed to decrypt !'

    # return decryption status, decrypted plain text
    return v, text


def encrypt_128a(key: bytes, nonce: bytes, data: np.ndarray, text: np.ndarray) -> Tuple[np.ndarray, bytes]:
    '''
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
    '''
    u8 = np.uint8

    assert u8().dtype == data.dtype, 'expected numpy ndarray[u8] as input'
    assert u8().dtype == text.dtype, 'expected numpy ndarray[u8] as input'

    d_len = data.size  # >= 0 bytes
    t_len = text.size  # >= 0 bytes
    cipher = np.empty(t_len, dtype=u8)  # allocate memory for keeping cipher

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce

    l0 = int.from_bytes(key[:8], 'big', signed=False)
    l1 = int.from_bytes(key[8:], 'big', signed=False)

    key_ = secret_key_t(limbs=(l0, l1))
    key_ = ct.byref(key_)

    l0 = int.from_bytes(nonce[:8], 'big', signed=False)
    l1 = int.from_bytes(nonce[8:], 'big', signed=False)

    nonce_ = nonce_t(limbs=(l0, l1))
    nonce_ = ct.byref(nonce_)

    args = [secret_key_tp, nonce_tp, data_t, len_t, text_t, len_t, cipher_t]

    # set function return type
    SO_LIB.encrypt_128a.restype = tag_t
    # set function signature
    SO_LIB.encrypt_128a.argtypes = args

    # encrypt using Ascon-128a
    tag = SO_LIB.encrypt_128a(key_, nonce_, data, d_len, text, t_len, cipher)

    # converting tag to byte array
    tag_ = tag.limbs[0].to_bytes(8, 'big') + tag.limbs[1].to_bytes(8, 'big')

    # return cipher text, tag ( 128 -bit )
    return cipher, tag_


def decrypt_128a(key: bytes, nonce: bytes, data: np.ndarray, cipher: np.ndarray, tag: bytes) -> Tuple[bool, np.ndarray]:
    '''
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
    '''
    u8 = np.uint8

    assert u8().dtype == data.dtype, 'expected numpy ndarray[u8] as input'
    assert u8().dtype == cipher.dtype, 'expected numpy ndarray[u8] as input'

    d_len = data.size  # >= 0 bytes
    c_len = cipher.size  # >= 0 bytes
    text = np.empty(c_len, dtype=u8)  # allocate memory for keeping plain text

    assert len(key) == 16  # 128 -bit secret key
    assert len(nonce) == 16  # 128 -bit nonce
    assert len(tag) == 16  # 128 -bit tag

    l0 = int.from_bytes(key[:8], 'big', signed=False)
    l1 = int.from_bytes(key[8:], 'big', signed=False)

    key_ = secret_key_t(limbs=(l0, l1))
    key_ = ct.byref(key_)

    l0 = int.from_bytes(nonce[:8], 'big', signed=False)
    l1 = int.from_bytes(nonce[8:], 'big', signed=False)

    nonce_ = nonce_t(limbs=(l0, l1))
    nonce_ = ct.byref(nonce_)

    l0 = int.from_bytes(tag[:8], 'big', signed=False)
    l1 = int.from_bytes(tag[8:], 'big', signed=False)

    tag_ = tag_t(limbs=(l0, l1))
    tag_ = ct.byref(tag_)

    args = [secret_key_tp, nonce_tp, data_t,
            len_t, cipher_t, len_t, text_t, tag_tp]

    # set function return type
    SO_LIB.decrypt_128a.restype = ct.c_bool
    # set function signature
    SO_LIB.decrypt_128a.argtypes = args

    # decrypt using Ascon-128a
    v = SO_LIB.decrypt_128a(key_, nonce_, data, d_len,
                            cipher, c_len, text, tag_)

    assert v, 'tag doesn\'t match, failed to decrypt !'

    # return decryption status, decrypted plain text
    return v, text


if __name__ == '__main__':
    print('This is an importable library module !')
