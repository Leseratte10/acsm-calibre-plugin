import binascii
import unittest

from customcrypto import _asn1, _cipher
from customcrypto._kdf import pkcs12_kdf

from ._unittest_compat import TestCase

PLAINTEXT = binascii.unhexlify('00112233445566778899AABBCCDDEEFF')
DES_KEY = binascii.unhexlify('133457799BBCDFF1')
DES_PLAINTEXT = binascii.unhexlify('0123456789ABCDEF')
DES_CIPHERTEXT = binascii.unhexlify('85E813540F0AB405')


def zeros(length):
    return b'\x00' * length


def counting(length):
    return bytes(bytearray(range(length)))


def decrypt_block(cipher, key, block):
    """Decrypts a single block in ECB mode, with the cipher setup that decrypt() uses"""
    module, key, options = _cipher._block_cipher(cipher, key)
    return module.new(key, module.MODE_ECB, **options).decrypt(block)


class CipherTests(TestCase):

    def test_aes_fips197(self):
        # FIPS 197 appendix C
        for key_length, ciphertext in (
            (16, '69C4E0D86A7B0430D8CDB78070B4C55A'),
            (24, 'DDA97CA4864CDFE06EAF70A0EC0D7191'),
            (32, '8EA2B7CA516745BFEAFC49904B496089'),
        ):
            with self.subTest(key_length=key_length):
                self.assertEqual(PLAINTEXT, decrypt_block('aes', counting(key_length), binascii.unhexlify(ciphertext)))

    def test_des(self):
        self.assertEqual(DES_PLAINTEXT, decrypt_block('des', DES_KEY, DES_CIPHERTEXT))

    def test_tripledes_reducing_to_des(self):
        # Keys where two of the three DES keys are the same, also when only their
        # parity bits differ. PyCryptodome refuses them, OpenSSL decrypts them as
        # single DES with the remaining key.
        other = binascii.unhexlify('0E329232EA6D0D73')
        other_parity = bytes(bytearray(b ^ 1 for b in bytearray(other)))
        for key in (DES_KEY * 3, DES_KEY * 2, other * 2 + DES_KEY, DES_KEY + other * 2, other + other_parity + DES_KEY):
            with self.subTest(key=binascii.hexlify(key)):
                self.assertEqual(DES_PLAINTEXT, decrypt_block('tripledes', key, DES_CIPHERTEXT))

    def test_rc2_rfc2268(self):
        # The vectors where the effective key length is the key length, as in OpenSSL
        for key, plaintext, ciphertext in (
            ('ffffffffffffffff', 'ffffffffffffffff', '278b27e42e2f0d49'),
            ('3000000000000000', '1000000000000001', '30649edf9be7d2c2'),
            ('88bca90e90875a7f0f79c384627bafb2', '0000000000000000', '2269552ab0f85ca6'),
        ):
            with self.subTest(key=key):
                self.assertEqual(binascii.unhexlify(plaintext),
                                 decrypt_block('rc2', binascii.unhexlify(key), binascii.unhexlify(ciphertext)))

    def test_rc4_rfc6229(self):
        keystream = binascii.unhexlify('b2396305f03dc027ccc3524a0a1118a8')
        self.assertEqual(zeros(16), _cipher.decrypt('rc4', binascii.unhexlify('0102030405'), keystream, None))

    def test_cbc_and_padding(self):
        key = counting(16)
        ciphertext = zeros(16)
        decrypted = decrypt_block('aes', key, ciphertext)

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

    def test_pkcs12_kdf_passwords(self):
        # Vectors from OpenSSL's PKCS12KDF, which takes the BMPString as it is: 0000 for an
        # empty password, nothing for no password at all (None), and 0070 00e4 0073 0073
        # 0077 00f6 0072 0064 0000 for u'p\xe4ssw\xf6rd', which pkcs12_kdf() makes of these Latin-1
        # bytes since they aren't valid UTF-8. For the first one:
        #   openssl kdf -keylen 24 -kdfopt digest:SHA1 -kdfopt hexpass:0000 \
        #       -kdfopt hexsalt:0102030405060708 -kdfopt iter:2048 -kdfopt id:1 PKCS12KDF
        salt = binascii.unhexlify('0102030405060708')
        for password, expected in (
            (b'', 'D9E86745C0EB8303BFC880579A1C7A45F2073495A0E9CD6E'),
            (None, '3CDBB28C9AB3455FCC24A7052C3E328A30E7480309831A7B'),
            (b'p\xe4ssw\xf6rd', '92C296B1A4D035F43C7DC4914D01976580551FF3FA390475'),
        ):
            with self.subTest(password=password):
                self.assertEqual(binascii.unhexlify(expected), pkcs12_kdf('sha1', password, salt, 2048, 24, 1))


class Asn1Tests(TestCase):

    def test_der(self):
        # What BER allows and DER doesn't: indefinite lengths, lengths in more bytes than
        # needed, and strings in chunks, also nested ones. The chunks of a BIT STRING each
        # start with their number of unused bits, and [128] needs a tag of two more bytes.
        octets = b'x' * 300
        der = (b'\x30\x82\x01\x46'
               + b'\x03\x04\x04\xaa\xbb\xc0'          # BIT STRING with 4 unused bits
               + b'\x0c\x07gr\xc3\xbc\xc3\x9fe'       # UTF8String u'gr\xfc\xdfe'
               + b'\x04\x82\x01\x2c' + octets           # OCTET STRING of 300 bytes
               + b'\xbf\x81\x00\x03\x02\x01\x05')    # [128] with INTEGER 5
        ber = (b'\x30\x80'
               + b'\x23\x80' + b'\x03\x02\x00\xaa' + b'\x03\x03\x04\xbb\xc0' + b'\x00\x00'
               + b'\x2c\x80' + b'\x0c\x04gr\xc3\xbc' + b'\x0c\x03\xc3\x9fe' + b'\x00\x00'
               + b'\x24\x80' + b'\x04\x64' + octets[:100]
               + b'\x24\x80' + b'\x04\x81\xc8' + octets[100:] + b'\x00\x00' + b'\x00\x00'
               + b'\xbf\x81\x00\x80' + b'\x02\x01\x05' + b'\x00\x00'
               + b'\x00\x00')
        self.assertEqual(der, _asn1.der(_asn1.load(ber)))

        # DER stays as it is, and a length in more bytes than needed gets shorter
        self.assertEqual(der, _asn1.der(_asn1.load(der)))
        self.assertEqual(b'\x30\x03\x02\x01\x01', _asn1.der(_asn1.load(b'\x30\x83\x00\x00\x03\x02\x01\x01')))

        with self.assertRaisesRegex(ValueError, 'Expected chunks of ASN.1 tag 4'):
            _asn1.der(_asn1.load(b'\x24\x80\x02\x01\x01\x00\x00'))


if __name__ == '__main__':
    unittest.main()
