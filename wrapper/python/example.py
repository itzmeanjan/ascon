#!/usr/bin/python3

import ascon as asc
import numpy as np


def main():
    # prepare 64 random bytes, to be used as input to Ascon-{Hash, HashA}
    msg = np.random.randint(0, high=0xFF, size=64, dtype=np.uint8)
    print(f"Message            : {msg.tobytes().hex()}")

    # compute Ascon-Hash digest
    digest = asc.hash(msg)
    print(f"Ascon-Hash Digest  : {digest.tobytes().hex()}")

    # compute Ascon-HashA digest
    digest = asc.hash_a(msg)
    print(f"Ascon-HashA Digest : {digest.tobytes().hex()}")

    # prepare random 128 -bit secret key
    key128 = np.random.randint(0, high=0xFF, size=16, dtype=np.uint8).tobytes()
    # prepare random 160 -bit secret key
    key160 = np.random.randint(0, high=0xFF, size=20, dtype=np.uint8).tobytes()
    # prepare random 128 -bit public message nonce
    nonce = np.random.randint(0, high=0xFF, size=16, dtype=np.uint8).tobytes()
    # prepare random 32 -bytes associated data
    data = np.random.randint(0, high=0xFF, size=32, dtype=np.uint8)
    # prepare random 64 -bytes plain text
    text = np.random.randint(0, high=0xFF, size=64, dtype=np.uint8)

    # encrypt using Ascon-128, also generate authentication tag
    enc, tag = asc.encrypt_128(key128, nonce, data, text)
    # decrypt using Ascon-128, while also verifying authenticity
    f, dec = asc.decrypt_128(key128, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-128 !"
    assert (text == dec).all(), f"plain text & decrypted text don't match !"

    print("\nAscon-128\n")
    print(f"Plain Text          : {text.tobytes().hex()}")
    print(f"Associated Data     : {data.tobytes().hex()}")
    print(f"Encrypted Data      : {enc.tobytes().hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.tobytes().hex()}")

    # encrypt using Ascon-128a, also generate authentication tag
    enc, tag = asc.encrypt_128a(key128, nonce, data, text)
    # decrypt using Ascon-128a, while also verifying authenticity
    f, dec = asc.decrypt_128a(key128, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-128a !"
    assert (text == dec).all(), f"plain text & decrypted text don't match !"

    print("\nAscon-128a\n")
    print(f"Plain Text          : {text.tobytes().hex()}")
    print(f"Associated Data     : {data.tobytes().hex()}")
    print(f"Encrypted Data      : {enc.tobytes().hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.tobytes().hex()}")

    # encrypt using Ascon-80pq, also generate authentication tag
    enc, tag = asc.encrypt_80pq(key160, nonce, data, text)
    # decrypt using Ascon-80pq, while also verifying authenticity
    f, dec = asc.decrypt_80pq(key160, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-80pq !"
    assert (text == dec).all(), f"plain text & decrypted text don't match !"

    print("\nAscon-80pq\n")
    print(f"Plain Text          : {text.tobytes().hex()}")
    print(f"Associated Data     : {data.tobytes().hex()}")
    print(f"Encrypted Data      : {enc.tobytes().hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.tobytes().hex()}")


if __name__ == "__main__":
    main()
