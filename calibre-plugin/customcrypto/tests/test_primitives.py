import binascii
import unittest

from customcrypto import _cipher
from customcrypto._compat import int_to_bytes
from customcrypto._kdf import pkcs12_kdf

from ._unittest_compat import TestCase

PLAINTEXT = 0x00112233445566778899AABBCCDDEEFF


def zeros(length):
    return b'\x00' * length


def counting(length):
    return bytes(bytearray(range(length)))


class CipherTests(TestCase):

    def test_aes_fips197(self):
        # FIPS 197 appendix C
        for key_length, ciphertext in (
            (16, 0x69C4E0D86A7B0430D8CDB78070B4C55A),
            (24, 0xDDA97CA4864CDFE06EAF70A0EC0D7191),
            (32, 0x8EA2B7CA516745BFEAFC49904B496089),
        ):
            with self.subTest(key_length=key_length):
                self.assertEqual(PLAINTEXT, _cipher._aes(counting(key_length))(ciphertext))

    def test_des(self):
        self.assertEqual(0x0123456789ABCDEF, _cipher._des(binascii.unhexlify('133457799BBCDFF1'))(0x85E813540F0AB405))

    def test_tripledes_with_one_key_is_des(self):
        key = binascii.unhexlify('133457799BBCDFF1')
        self.assertEqual(0x0123456789ABCDEF, _cipher._des(key * 3)(0x85E813540F0AB405))

    def test_rc2_rfc2268(self):
        for key, plaintext, ciphertext in (
            ('ffffffffffffffff', 0xFFFFFFFFFFFFFFFF, 0x278B27E42E2F0D49),
            ('3000000000000000', 0x1000000000000001, 0x30649EDF9BE7D2C2),
            ('88bca90e90875a7f0f79c384627bafb2', 0, 0x2269552AB0F85CA6),
        ):
            with self.subTest(key=key):
                self.assertEqual(plaintext, _cipher._rc2(binascii.unhexlify(key))(ciphertext))

    def test_rc4_rfc6229(self):
        keystream = binascii.unhexlify('b2396305f03dc027ccc3524a0a1118a8')
        self.assertEqual(zeros(16), _cipher.decrypt('rc4', binascii.unhexlify('0102030405'), keystream, None))

    def test_cbc_and_padding(self):
        key = counting(16)
        ciphertext = zeros(16)
        decrypted = int_to_bytes(_cipher._aes(key)(0), 16)

        def iv_for(plaintext):
            # With a decrypt-only cipher, choose the IV that turns the block into plaintext
            return bytes(bytearray(a ^ b for a, b in zip(bytearray(decrypted), bytearray(plaintext))))

        self.assertEqual(b'hello', _cipher.decrypt('aes', key, ciphertext, iv_for(b'hello' + b'\x0b' * 11)))
        self.assertEqual(b'', _cipher.decrypt('aes', key, ciphertext, iv_for(b'\x10' * 16)))

        for plaintext in (b'hello' + b'\x0a' + b'\x0b' * 10, b'hello' + b'\x0b' * 10 + b'\x00', b'\x11' * 16):
            with self.subTest(plaintext=plaintext):
                with self.assertRaisesRegex(ValueError, 'invalid padding'):
                    _cipher.decrypt('aes', key, ciphertext, iv_for(plaintext))

        for data in (b'', b'\x00' * 15, b'\x00' * 17):
            with self.subTest(length=len(data)):
                with self.assertRaisesRegex(ValueError, 'multiple of 16'):
                    _cipher.decrypt('aes', key, data, zeros(16))

    def test_argument_checks(self):
        for cipher, key, iv, message in (
            ('aes', zeros(15), zeros(16), 'AES key'),
            ('aes', zeros(16), zeros(8), 'IV must be 16'),
            ('des', zeros(16), zeros(8), 'DES key'),
            ('tripledes', zeros(8), zeros(8), '3DES key'),
            ('rc2', zeros(4), zeros(8), 'RC2 key'),
            ('rc4', zeros(17), None, 'RC4 key'),
            ('rc5', zeros(16), zeros(8), 'Unsupported cipher'),
        ):
            with self.subTest(cipher=cipher, message=message):
                with self.assertRaisesRegex(ValueError, message):
                    _cipher.decrypt(cipher, key, zeros(16), iv)


class KdfTests(TestCase):

    def test_pkcs12_kdf(self):
        # Vector from the oscrypto test suite; 24 bytes from SHA-1 needs two rounds
        key = pkcs12_kdf('sha1', b'sesame', b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', 2048, 24, 1)
        self.assertEqual(binascii.unhexlify('7CD9FD3E2B3BE7691A44E3BEF0F9EA0FB9B897D4E325D9D1'), key)


if __name__ == '__main__':
    unittest.main()
