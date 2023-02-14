#!/usr/bin/python3

import ascon as asc
from random import randbytes


def main():
    # ---------------------------------------------
    msg = randbytes(64)
    print(f"Message            : {msg.hex()}")
    # ---------------------------------------------

    # compute Ascon-Hash digest
    digest = asc.hash(msg)
    print(f"Ascon-Hash Digest  : {digest.hex()}")

    # compute Ascon-HashA digest
    digest = asc.hash_a(msg)
    print(f"Ascon-HashA Digest : {digest.hex()}")

    # ---------------------------------------------
    key128 = randbytes(16)
    key160 = randbytes(20)
    nonce = randbytes(16)
    data = randbytes(32)
    text = randbytes(64)
    # ---------------------------------------------

    # encrypt using Ascon-128, also generate authentication tag
    enc, tag = asc.encrypt_128(key128, nonce, data, text)
    # decrypt using Ascon-128, while also verifying authenticity
    f, dec = asc.decrypt_128(key128, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-128 !"
    assert text == dec, f"plain text & decrypted text don't match !"

    print("\nAscon-128\n")
    print(f"Plain Text          : {text.hex()}")
    print(f"Associated Data     : {data.hex()}")
    print(f"Encrypted Data      : {enc.hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.hex()}")

    # ---------------------------------------------

    # encrypt using Ascon-128a, also generate authentication tag
    enc, tag = asc.encrypt_128a(key128, nonce, data, text)
    # decrypt using Ascon-128a, while also verifying authenticity
    f, dec = asc.decrypt_128a(key128, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-128a !"
    assert text == dec, f"plain text & decrypted text don't match !"

    print("\nAscon-128a\n")
    print(f"Plain Text          : {text.hex()}")
    print(f"Associated Data     : {data.hex()}")
    print(f"Encrypted Data      : {enc.hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.hex()}")

    # ---------------------------------------------

    # encrypt using Ascon-80pq, also generate authentication tag
    enc, tag = asc.encrypt_80pq(key160, nonce, data, text)
    # decrypt using Ascon-80pq, while also verifying authenticity
    f, dec = asc.decrypt_80pq(key160, nonce, data, enc, tag)

    assert f, f"verified decryption failed for Ascon-80pq !"
    assert text == dec, f"plain text & decrypted text don't match !"

    print("\nAscon-80pq\n")
    print(f"Plain Text          : {text.hex()}")
    print(f"Associated Data     : {data.hex()}")
    print(f"Encrypted Data      : {enc.hex()}")
    print(f"Authentication Tag  : {tag.hex()}")
    print(f"Decrypted Data      : {dec.hex()}")


if __name__ == "__main__":
    main()
