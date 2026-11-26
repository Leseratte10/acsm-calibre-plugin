"""
The ciphers PKCS#12 files use: AES, DES, 3DES and RC2 in CBC mode with
PKCS#5/#7 padding, plus RC4.

The ciphers come from PyCryptodome, or from PyCrypto 2.6, which Calibre 3
bundles. This module only checks the parameters, handles the cases where
PyCryptodome differs from OpenSSL (and so from oscrypto), and removes the
padding. Anything used here has to exist in PyCrypto 2.6 too.
"""

try:
    from Cryptodome.Cipher import AES, ARC2, ARC4, DES, DES3
except ImportError:
    from Crypto.Cipher import AES, ARC2, ARC4, DES, DES3


def decrypt(cipher, key, data, iv):
    """
    :param cipher:
        "aes", "des", "tripledes", "rc2" or "rc4"

    :param iv:
        The IV, or None for RC4

    :return:
        The plaintext with padding removed
    """

    if cipher == 'rc4':
        if not 5 <= len(key) <= 16:
            raise ValueError('RC4 key must be 5 to 16 bytes long - is %d' % len(key))
        return ARC4.new(key).decrypt(data)

    module, key, options = _block_cipher(cipher, key)
    block_size = module.block_size
    if iv is None or len(iv) != block_size:
        raise ValueError('IV must be %d bytes long' % block_size)
    if not data or len(data) % block_size:
        raise ValueError('Ciphertext length must be a non-zero multiple of %d' % block_size)

    output = bytearray(module.new(key, module.MODE_CBC, iv, **options).decrypt(data))

    # PyCrypto 2.6 has no Util.Padding.unpad()
    pad = output[-1]
    if not 1 <= pad <= block_size or output[-pad:] != bytearray([pad]) * pad:
        raise ValueError('Decryption failed - invalid padding, the password may be incorrect')
    return bytes(output[:-pad])


def _block_cipher(cipher, key):
    """
    Checks the key length of a block cipher

    :return:
        A three-element tuple of the PyCryptodome cipher module, the key to
        use with it, and the keyword arguments for its new() function
    """

    if cipher == 'aes':
        if len(key) not in (16, 24, 32):
            raise ValueError('AES key must be 16, 24 or 32 bytes long - is %d' % len(key))
        return AES, key, {}

    if cipher == 'des':
        if len(key) != 8:
            raise ValueError('DES key must be 8 bytes long - is %d' % len(key))
        return DES, key, {}

    if cipher == 'tripledes':
        if len(key) not in (16, 24):
            raise ValueError('3DES key must be 16 or 24 bytes long - is %d' % len(key))
        # PyCryptodome refuses keys that reduce 3DES to single DES, which OpenSSL
        # accepts. Decryption is D(K1, E(K2, D(K3, block))), so it is D(K3, block)
        # if K1 and K2 are the same DES key, and D(K1, block) if K2 and K3 are.
        k1, k2, k3 = key[:8], key[8:16], key[16:] or key[:8]
        if _same_des_key(k1, k2):
            return DES, k3, {}
        if _same_des_key(k2, k3):
            return DES, k1, {}
        return DES3, key, {}

    if cipher == 'rc2':
        if not 5 <= len(key) <= 16:
            raise ValueError('RC2 key must be 5 to 16 bytes long - is %d' % len(key))
        # OpenSSL, and therefore oscrypto, uses the key length as the effective key length
        return ARC2, key, {'effective_keylen': 8 * len(key)}

    raise ValueError('Unsupported cipher %r' % cipher)


def _same_des_key(a, b):
    # DES ignores the lowest bit of each key byte, its parity bit
    return bytearray(x | 1 for x in bytearray(a)) == bytearray(x | 1 for x in bytearray(b))
