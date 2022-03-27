#!/usr/bin/python3

'''
  Before using `ascon` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then function calls are forwarded to respective DPC++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
'''

import ctypes as ct
from genericpath import exists
from posixpath import abspath
import numpy as np

SO_PATH: str = abspath('../libascon_hash.so')
assert exists(SO_PATH), '`make lib` to generate shared library !'

SO_LIB: ct.CDLL = ct.CDLL(SO_PATH)

# setting proper data type for function arguments
len_t = ct.c_size_t
msg_t = np.ctypeslib.ndpointer(
    dtype=np.uint8, ndim=1, flags='CONTIGUOUS')
digest_t = np.ctypeslib.ndpointer(
    dtype=np.uint8, ndim=1, flags='CONTIGUOUS')


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


if __name__ == '__main__':
    print('This is an importable library module !')
