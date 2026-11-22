"""
Password-based key derivation used by PKCS#12 files.

pkcs12_kdf is derived from oscrypto._pkcs12. PBKDF2 comes straight from
hashlib.pbkdf2_hmac, so it is not reimplemented here.
"""

import hashlib

from ._compat import int_from_bytes, int_to_bytes


def pkcs12_kdf(hash_algorithm, password, salt, iterations, key_length, id_):
    """
    KDF from RFC 7292 appendix B.2

    :param hash_algorithm:
        "sha1", "sha224", "sha256", "sha384" or "sha512"

    :param password:
        A UTF-8 byte string, converted to a NUL-terminated BMPString as the RFC requires

    :param id_:
        1 to derive a key, 2 for an IV, 3 for a MAC key

    :return:
        A byte string of key_length bytes
    """

    password = password.decode('utf-8').encode('utf-16be') + b'\x00\x00'
    v = hashlib.new(hash_algorithm).block_size

    def fill(data):
        # Repeats data up to the next multiple of v bytes
        return (data * v)[:(len(data) + v - 1) // v * v]

    d = int_to_bytes(id_, 1) * v
    i = fill(salt) + fill(password)
    output = b''
    while len(output) < key_length:
        a = pbkdf1(hash_algorithm, d, i, iterations)  # A = H^iterations(D || I)
        output += a
        # Adds B + 1 to each v byte block of I, where B is A repeated to v bytes
        b = int_from_bytes(fill(a)) + 1
        i = b''.join(
            int_to_bytes((int_from_bytes(i[n:n + v]) + b) % (1 << 8 * v), v)
            for n in range(0, len(i), v)
        )
    return output[:key_length]


def pbkdf1(hash_algorithm, password, salt, iterations, key_length=None):
    """
    PBKDF1 from PKCS#5 (RFC 8018 section 5.1): password + salt hashed
    iterations times, truncated to key_length bytes if given
    """

    if iterations < 1:
        raise ValueError('iterations must be greater than 0 - is %d' % iterations)
    output = password + salt
    for _ in range(iterations):
        output = hashlib.new(hash_algorithm, output).digest()
    return output[:key_length]
