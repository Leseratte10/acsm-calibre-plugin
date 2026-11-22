"""
Decrypt-only, pure-Python versions of the ciphers PKCS#12 files use:
AES, DES, 3DES and RC2 in CBC mode with PKCS#5/#7 padding, plus RC4.

oscrypto hands these to OpenSSL, CNG or CommonCrypto. They are reimplemented
here so this package has no native dependencies. The code is not constant
time. It is only meant for decrypting a key file at load time.
"""

import binascii
import struct

from ._compat import int_from_bytes, int_to_bytes


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
        return _rc4(key, data)

    if cipher == 'aes':
        if len(key) not in (16, 24, 32):
            raise ValueError('AES key must be 16, 24 or 32 bytes long - is %d' % len(key))
        block_size, decrypt_block = 16, _aes(key)

    elif cipher == 'des':
        if len(key) != 8:
            raise ValueError('DES key must be 8 bytes long - is %d' % len(key))
        block_size, decrypt_block = 8, _des(key)

    elif cipher == 'tripledes':
        if len(key) not in (16, 24):
            raise ValueError('3DES key must be 16 or 24 bytes long - is %d' % len(key))
        block_size, decrypt_block = 8, _des(key if len(key) == 24 else key + key[:8])

    elif cipher == 'rc2':
        if not 5 <= len(key) <= 16:
            raise ValueError('RC2 key must be 5 to 16 bytes long - is %d' % len(key))
        block_size, decrypt_block = 8, _rc2(key)
        
    else:
        raise ValueError('Unsupported cipher %r' % cipher)

    if iv is None or len(iv) != block_size:
        raise ValueError('IV must be %d bytes long' % block_size)
    if not data or len(data) % block_size:
        raise ValueError('Ciphertext length must be a non-zero multiple of %d' % block_size)

    output = bytearray()
    previous = int_from_bytes(iv)
    for offset in range(0, len(data), block_size):
        block = int_from_bytes(data[offset:offset + block_size])
        output += int_to_bytes(decrypt_block(block) ^ previous, block_size)
        previous = block

    pad = output[-1]
    if not 1 <= pad <= block_size or output[-pad:] != bytearray([pad]) * pad:
        raise ValueError('Decryption failed - invalid padding, the password may be incorrect')
    return bytes(output[:-pad])


# AES (FIPS 197), table driven decryption with the equivalent inverse cipher.
# Tables are generated at import from GF(2^8) arithmetic.

def _aes_tables():
    exp = [0] * 255
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)  # multiply by the generator 3

    def mul(a, b):
        return exp[(log[a] + log[b]) % 255] if a and b else 0

    sbox = [0] * 256
    inv_sbox = [0] * 256
    for x in range(256):
        s = exp[-log[x] % 255] if x else 0
        s ^= ((s << 1) | (s >> 7)) ^ ((s << 2) | (s >> 6)) ^ ((s << 3) | (s >> 5)) ^ ((s << 4) | (s >> 4))
        s = (s ^ 0x63) & 0xFF
        sbox[x] = s
        inv_sbox[s] = x

    # Td0 combines InvSubBytes with an InvMixColumns column, Td1-Td3 are its rotations
    td0 = [mul(s, 14) << 24 | mul(s, 9) << 16 | mul(s, 13) << 8 | mul(s, 11) for s in inv_sbox]
    tds = [[((t >> n) | (t << (32 - n))) & 0xFFFFFFFF for t in td0] for n in (0, 8, 16, 24)]
    return [sbox, inv_sbox] + tds


_SBOX, _INV_SBOX, _TD0, _TD1, _TD2, _TD3 = _aes_tables()


def _aes(key):
    nk = len(key) // 4
    nr = nk + 6

    def sub_word(w):
        return _SBOX[w >> 24] << 24 | _SBOX[(w >> 16) & 255] << 16 | _SBOX[(w >> 8) & 255] << 8 | _SBOX[w & 255]

    def inv_mix_columns(w):
        return _TD0[_SBOX[w >> 24]] ^ _TD1[_SBOX[(w >> 16) & 255]] ^ _TD2[_SBOX[(w >> 8) & 255]] ^ _TD3[_SBOX[w & 255]]

    w = [int_from_bytes(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = w[-1]
        if i % nk == 0:
            t = sub_word(((t << 8) | (t >> 24)) & 0xFFFFFFFF) ^ (rcon << 24)
            rcon = (rcon << 1) ^ (0x11B if rcon & 0x80 else 0)
        elif nk > 6 and i % nk == 4:
            t = sub_word(t)
        w.append(w[i - nk] ^ t)

    # Round keys in reverse order, with InvMixColumns applied to the inner ones
    rounds = [w[4 * r:4 * r + 4] for r in range(nr, -1, -1)]
    first, last = rounds[0], rounds[-1]
    middle = [[inv_mix_columns(x) for x in k] for k in rounds[1:-1]]
    td0, td1, td2, td3, si = _TD0, _TD1, _TD2, _TD3, _INV_SBOX

    def decrypt_block(block):
        s0 = (block >> 96) ^ first[0]
        s1 = ((block >> 64) & 0xFFFFFFFF) ^ first[1]
        s2 = ((block >> 32) & 0xFFFFFFFF) ^ first[2]
        s3 = (block & 0xFFFFFFFF) ^ first[3]
        for k in middle:
            s0, s1, s2, s3 = (
                td0[s0 >> 24] ^ td1[(s3 >> 16) & 255] ^ td2[(s2 >> 8) & 255] ^ td3[s1 & 255] ^ k[0],
                td0[s1 >> 24] ^ td1[(s0 >> 16) & 255] ^ td2[(s3 >> 8) & 255] ^ td3[s2 & 255] ^ k[1],
                td0[s2 >> 24] ^ td1[(s1 >> 16) & 255] ^ td2[(s0 >> 8) & 255] ^ td3[s3 & 255] ^ k[2],
                td0[s3 >> 24] ^ td1[(s2 >> 16) & 255] ^ td2[(s1 >> 8) & 255] ^ td3[s0 & 255] ^ k[3],
            )

        def final(a, b, c, d, k):
            return (si[a >> 24] << 24 | si[(b >> 16) & 255] << 16 | si[(c >> 8) & 255] << 8 | si[d & 255]) ^ k

        return (
            final(s0, s3, s2, s1, last[0]) << 96 | final(s1, s0, s3, s2, last[1]) << 64
            | final(s2, s1, s0, s3, last[2]) << 32 | final(s3, s2, s1, s0, last[3])
        )

    return decrypt_block


# DES (FIPS 46-3). An 8 byte key is single DES, a 24 byte key is 3DES EDE.

_IP = [start - 8 * i for start in (58, 60, 62, 64, 57, 59, 61, 63) for i in range(8)]
_FP = [_IP.index(i) + 1 for i in range(1, 65)]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOXES = [  # S1..S8, four rows of 16 nibbles each
    'e4d12fb83a6c59070f74e2d1a6cb953841e8d62bfc973a50fc8249175b3ea06d',
    'f18e6b34972dc05a3d47f28ec01a69b50e7ba4d158c6932fd8a13f42b67c05e9',
    'a09e63f51dc7b428d709346a285ecbf1d6498f30b12c5ae71ad069874fe3b52c',
    '7de3069a1285bc4fd8b56f03472c1ae9a690cb7df13e52843f06a1d8945bc72e',
    '2c417ab6853fd0e9eb2c47d150fa3986421bad78f9c5630eb8c71e2d6f09a453',
    'c1af92680d34e75baf427c9561de0b389ef528c3704a1db6432c95fabe17608d',
    '4b2ef08d3c975a61d0b7491ae35c2f8614bdc37eaf6805926bd814a7950fe23c',
    'd2846fb1a93e50c71fd8a374c56b0e927b419ce206adf35821e74a8dfc90356b',
]


def _permute(value, table, width):
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (width - position)) & 1)
    return result


# S-box lookups combined with the P permutation, indexed by the 6 bit S-box input
_SP = [
    [
        _permute(int(box[((b >> 4) & 2 | b & 1) * 16 + ((b >> 1) & 15)], 16) << (28 - 4 * i), _P, 32)
        for b in range(64)
    ]
    for i, box in enumerate(_SBOXES)
]


def _des_subkeys(key):
    cd = _permute(int_from_bytes(key), _PC1, 64)
    c, d = cd >> 28, cd & 0xFFFFFFF
    subkeys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
        k = _permute((c << 28) | d, _PC2, 56)
        subkeys.append([(k >> (42 - 6 * i)) & 63 for i in range(8)])
    return subkeys


def _des(key):
    keys = [_des_subkeys(key[i:i + 8]) for i in range(0, len(key), 8)]
    # Decrypting runs the subkeys backwards, and 3DES EDE decryption is D(K1, E(K2, D(K3, block)))
    schedule = [subkeys if n % 2 else subkeys[::-1] for n, subkeys in enumerate(reversed(keys))]
    sp0, sp1, sp2, sp3, sp4, sp5, sp6, sp7 = _SP

    def decrypt_block(block):
        x = _permute(block, _IP, 64)
        left, right = x >> 32, x & 0xFFFFFFFF
        # The final and initial permutations between 3DES stages cancel out
        for subkeys in schedule:
            for k in subkeys:
                e = ((right & 1) << 33) | (right << 1) | (right >> 31)
                left, right = right, left ^ (
                    sp0[((e >> 28) & 63) ^ k[0]] | sp1[((e >> 24) & 63) ^ k[1]]
                    | sp2[((e >> 20) & 63) ^ k[2]] | sp3[((e >> 16) & 63) ^ k[3]]
                    | sp4[((e >> 12) & 63) ^ k[4]] | sp5[((e >> 8) & 63) ^ k[5]]
                    | sp6[((e >> 4) & 63) ^ k[6]] | sp7[(e & 63) ^ k[7]]
                )
            left, right = right, left
        return _permute((left << 32) | right, _FP, 64)

    return decrypt_block


# RC2 (RFC 2268), with the effective key length equal to the key length, as
# OpenSSL (and therefore oscrypto) uses it

_PITABLE = bytearray(binascii.unhexlify(
    'd978f9c419ddb5ed28e9fd794aa0d89dc67e37832b76538e624c6488448bfba2'
    '179a59f587b34f1361456d8d09817d32bd8f40eb86b77b0bf09521225c6b4e82'
    '54d66593ce60b21c7356c014a78cf1dc1275ca1f3bbee4d1423dd430a33cb626'
    '6fbf0eda4669075727f21d9bbc944303f811c7f690ef3ee706c3d52fc8661ed7'
    '08e8eade8052eef784aa72ac354d6a2a961ad2715a1549744b9fd05e0418a4ec'
    'c2e0416e0f51cbcc2491af50a1f47039997c3a8523b8b47afc02365b25559731'
    '2d5dfa98e38a92ae05df2910676cbac9d300e6cfe19ea82c6316013f58e289a9'
    '0d38341bab33ffb0bb480c5fb9b1cd2ec5f3db47e5a59c770aa62068fe7fc1ad'
))


def _rc2(key):
    t = len(key)
    expanded = bytearray(128)
    expanded[:t] = key
    for i in range(t, 128):
        expanded[i] = _PITABLE[(expanded[i - 1] + expanded[i - t]) & 255]
    expanded[128 - t] = _PITABLE[expanded[128 - t]]
    for i in range(127 - t, -1, -1):
        expanded[i] = _PITABLE[expanded[i + 1] ^ expanded[i + t]]
    k = struct.unpack('<64H', bytes(expanded))

    def decrypt_block(block):
        r = list(struct.unpack('<4H', int_to_bytes(block, 8)))
        j = 63
        for round_ in range(16):
            for i, shift in ((3, 5), (2, 3), (1, 2), (0, 1)):
                r[i] = ((r[i] >> shift) | (r[i] << (16 - shift))) & 0xFFFF
                r[i] = (r[i] - k[j] - (r[i - 1] & r[i - 2]) - (~r[i - 1] & r[i - 3])) & 0xFFFF
                j -= 1
            if round_ in (4, 10):
                for i in (3, 2, 1, 0):
                    r[i] = (r[i] - k[r[i - 1] & 63]) & 0xFFFF
        return int_from_bytes(struct.pack('<4H', *r))

    return decrypt_block


def _rc4(key, data):
    key = bytearray(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    output = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(bytearray(data)):
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        output[n] = byte ^ s[(s[i] + s[j]) & 255]
    return bytes(output)
