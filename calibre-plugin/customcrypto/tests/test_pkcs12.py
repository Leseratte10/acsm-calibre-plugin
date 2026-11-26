import base64
import hashlib
import hmac
import os
import unittest

try:
    from Cryptodome.Cipher import AES, ARC2, DES, DES3
except ImportError:
    from Crypto.Cipher import AES, ARC2, DES, DES3

from customcrypto import keys
from customcrypto._kdf import pkcs12_kdf

from ._unittest_compat import TestCase

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')
PASSWORD = b'password123'
UNICODE_PASSWORD = u'p\xe4ssw\xf6rd\u20ac'.encode('utf-8')
LATIN1_PASSWORD = u'p\xe4ssw\xf6rd'.encode('latin-1')


def read(name):
    with open(os.path.join(FIXTURES, name), 'rb') as f:
        return f.read()


def read_pem(name):
    """The DER bytes of a PEM file with a single block"""
    return base64.b64decode(b''.join(line for line in read(name).splitlines() if not line.startswith(b'-----')))


# Expected (key, cert, extra certs) for the fixtures. The test-*.p12 files and
# their expected values come from the oscrypto test suite.
RSA = ('test-pkcs8-der.key', 'test-der.crt', [])
DSA = ('test-pkcs8-dsa-der.key', 'test-dsa-der.crt', [])
CHAIN = ('test-third-pkcs8-der.key', 'test-third-der.crt', ['test-inter-der.crt', 'test-der.crt'])


def ec(curve):
    return ('ec-%s-pkcs8-der.key' % curve, 'ec-%s-der.crt' % curve, ['test-der.crt'])


FILES = [
    # Legacy OpenSSL 1.x defaults: 3DES or RC2-40 keys, RC2-40 certs, SHA-1 MAC
    ('test-tripledes.p12', PASSWORD, RSA),
    ('test-tripledes-blank.p12', b'', RSA),
    ('test-tripledes-blank.p12', None, RSA),
    ('test-rc2.p12', PASSWORD, RSA),
    ('test-dsa.p12', PASSWORD, DSA),
    ('test-third.p12', PASSWORD, CHAIN),
    # OpenSSL 3 default: PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC, SHA-256 MAC
    ('openssl-default.p12', PASSWORD, RSA),
    ('openssl-chain.p12', PASSWORD, CHAIN),
    ('openssl-blank.p12', b'', RSA),
    ('openssl-blank.p12', None, RSA),
    ('openssl-unicode.p12', UNICODE_PASSWORD, RSA),
    ('openssl-unicode-legacy.p12', UNICODE_PASSWORD, RSA),
    # Not valid UTF-8, so OpenSSL converts it byte by byte
    ('openssl-latin1.p12', LATIN1_PASSWORD, RSA),
    ('openssl-latin1-legacy.p12', LATIN1_PASSWORD, RSA),
    # PBES2 ciphers
    ('openssl-aes128-aes192.p12', PASSWORD, RSA),
    ('openssl-des3-des.p12', PASSWORD, RSA),
    ('openssl-rc2-rc2-40.p12', PASSWORD, RSA),
    ('openssl-rc2-64-none.p12', PASSWORD, RSA),
    # PKCS#5 PBES1
    ('openssl-md5-des-sha1-rc2-64.p12', PASSWORD, RSA),
    ('openssl-sha1-des-md5-rc2-64.p12', PASSWORD, RSA),
    # PKCS#12 PBE
    ('openssl-rc4-128-rc4-40.p12', PASSWORD, RSA),
    ('openssl-2des-rc2-128.p12', PASSWORD, RSA),
    # MAC variants, unencrypted key bag and certificates
    ('openssl-none-sha512mac.p12', PASSWORD, RSA),
    ('openssl-sha224mac.p12', PASSWORD, RSA),
    ('openssl-sha384mac.p12', PASSWORD, RSA),
    ('openssl-nomac.p12', PASSWORD, RSA),
    ('openssl-noiter.p12', PASSWORD, RSA),
    # EC keys, each with an extra RSA certificate
    ('openssl-ec-prime256v1.p12', PASSWORD, ec('prime256v1')),
    ('openssl-ec-secp384r1.p12', PASSWORD, ec('secp384r1')),
    ('openssl-ec-secp521r1.p12', PASSWORD, ec('secp521r1')),
]


# Tiny DER/BER helpers for building test inputs, independent of customcrypto._asn1

def tlv(tag, contents):
    length = len(contents)
    if length < 0x80:
        header = bytearray([length])
    else:
        encoded = bytearray()
        while length:
            encoded.insert(0, length & 0xFF)
            length >>= 8
        header = bytearray([0x80 | len(encoded)]) + encoded
    return bytes(bytearray([tag]) + header + bytearray(contents))


def read_tlv(data, pos=0):
    """Returns (tag, contents, end) for a DER TLV with a single byte tag"""
    tag, length = bytearray(data[pos:pos + 2])
    pos += 2
    if length & 0x80:
        num = length & 0x7F
        length = 0
        for byte in bytearray(data[pos:pos + num]):
            length = (length << 8) | byte
        pos += num
    return tag, data[pos:pos + length], pos + length


def der_children(contents):
    result = []
    pos = 0
    while pos < len(contents):
        start = pos
        pos = read_tlv(contents, pos)[2]
        result.append(contents[start:pos])
    return result


def to_ber(der, chunk_size=16):
    """
    Re-encodes a DER value the way Windows and some Java versions do: every
    constructed value gets an indefinite length, and OCTET STRINGs (including
    [0] IMPLICIT ones) are split into chunks. Values inside OCTET STRINGs are
    left alone, so a PKCS#12 MAC over them stays valid.
    """

    tag, contents, _ = read_tlv(der)
    if tag in (0x04, 0x80):
        chunks = [contents[i:i + chunk_size] for i in range(0, len(contents), chunk_size)]
        return bytes(bytearray([tag | 0x20, 0x80])) + b''.join(tlv(0x04, c) for c in chunks) + b'\x00\x00'
    if tag & 0x20:
        return bytes(bytearray([tag, 0x80])) + b''.join(to_ber(c, chunk_size) for c in der_children(contents)) + b'\x00\x00'
    return der


def oid(dotted):
    arcs = [int(a) for a in dotted.split('.')]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        part = bytearray([arc & 0x7F])
        arc >>= 7
        while arc:
            part.insert(0, 0x80 | (arc & 0x7F))
            arc >>= 7
        body += part
    return tlv(0x06, bytes(body))


def seq(*items):
    return tlv(0x30, b''.join(items))


def explicit0(value):
    return tlv(0xA0, value)


def data_content_info(contents):
    return seq(oid('1.2.840.113549.1.7.1'), explicit0(tlv(0x04, contents)))


def pfx(safe_contents_list):
    """An unencrypted PKCS#12 without a MAC"""
    auth_safe = seq(*[data_content_info(seq(*bags)) for bags in safe_contents_list])
    return seq(tlv(0x02, b'\x03'), data_content_info(auth_safe))


def bag(bag_type, value):
    return seq(oid('1.2.840.113549.1.12.10.1.%d' % bag_type), explicit0(value))


def cert_bag(cert_der):
    return bag(3, seq(oid('1.2.840.113549.1.9.22.1'), explicit0(tlv(0x04, cert_der))))


# For files with encrypted keys and MACs

SALT = b'saltsalt'
ITERATIONS = 2048
IV8 = b'01234567'
IV16 = b'0123456789abcdef'


def integer(value):
    """A DER INTEGER, for a value that isn't negative"""
    encoded = bytearray([value & 0xFF])
    value >>= 8
    while value or encoded[0] & 0x80:
        encoded.insert(0, value & 0xFF)
        value >>= 8
    return tlv(0x02, bytes(encoded))


def cbc_encrypt(cipher, key, iv, plaintext, **options):
    """Encrypts in CBC mode with PKCS#7 padding, as PKCS#12 files do"""
    pad = cipher.block_size - len(plaintext) % cipher.block_size
    return cipher.new(key, cipher.MODE_CBC, iv, **options).encrypt(plaintext + bytes(bytearray([pad] * pad)))


def pbkdf2(password, length):
    return hashlib.pbkdf2_hmac('sha1', password, SALT, ITERATIONS, length)


def pbes2(scheme, ciphertext, key_length=None):
    """An EncryptedPrivateKeyInfo for PBES2 with PBKDF2-HMAC-SHA1, the optional key
    length and the AlgorithmIdentifier of the encryption scheme"""
    kdf_params = [tlv(0x04, SALT), integer(ITERATIONS)] + ([integer(key_length)] if key_length else [])
    algorithm = seq(oid('1.2.840.113549.1.5.13'), seq(seq(oid('1.2.840.113549.1.5.12'), seq(*kdf_params)), scheme))
    return seq(algorithm, tlv(0x04, ciphertext))


def aes128_key_bag(plaintext, password=PASSWORD, key_length=None):
    """A shrouded key bag with PBES2 and AES-128"""
    scheme = seq(oid('2.16.840.1.101.3.4.1.2'), tlv(0x04, IV16))
    return bag(2, pbes2(scheme, cbc_encrypt(AES, pbkdf2(password, 16), IV16, plaintext), key_length))


def pfx_with_mac(bags, kdf_password):
    """An unencrypted PKCS#12 file with a SHA-1 MAC, made with the password as pkcs12_kdf()
    takes it: b'' for an empty one, None for no password at all"""
    auth_safe = seq(data_content_info(seq(*bags)))
    mac_key = pkcs12_kdf('sha1', kdf_password, SALT, ITERATIONS, 20, 3)
    digest = hmac.new(mac_key, auth_safe, hashlib.sha1).digest()
    mac_data = seq(seq(seq(oid('1.3.14.3.2.26'), tlv(0x05, b'')), tlv(0x04, digest)), tlv(0x04, SALT), integer(ITERATIONS))
    return seq(tlv(0x02, b'\x03'), data_content_info(auth_safe), mac_data)


class ParsePkcs12Tests(TestCase):

    def assertResult(self, result, expected):
        key, cert, extra = result
        key_name, cert_name, extra_names = expected
        self.assertIsInstance(key, keys.PrivateKeyInfo)
        self.assertIsInstance(cert, keys.Certificate)
        self.assertEqual(read(key_name), key.dump())
        self.assertEqual(read(cert_name), cert.dump())
        self.assertEqual([read(name) for name in extra_names], [c.dump() for c in extra])

    def test_files(self):
        for filename, password, expected in FILES:
            with self.subTest(filename=filename, password=password):
                self.assertResult(keys.parse_pkcs12(read(filename), password), expected)

    def test_usage_from_readme(self):
        mock_p12_data = read('openssl-default.p12')
        mock_p12_password = PASSWORD

        privkey, cert, _ = keys.parse_pkcs12(mock_p12_data, mock_p12_password)
        cert = cert.dump()
        privkey = privkey.dump()

        self.assertEqual(read('test-der.crt'), cert)
        self.assertEqual(read('test-pkcs8-der.key'), privkey)

    def test_certs_only(self):
        key, cert, extra = keys.parse_pkcs12(read('openssl-certs-only.p12'), PASSWORD)
        self.assertIsNone(key)
        # The first certificate in the file, then the others in file order
        self.assertEqual(read('test-third-der.crt'), cert.dump())
        self.assertEqual([read('test-inter-der.crt'), read('test-der.crt')], [c.dump() for c in extra])


    def test_several_pairs(self):
        # The first key and the first certificate in the file are picked, so the
        # pair that comes first wins
        pairs = [('test-pkcs8-der.key', 'test-der.crt'), ('test-third-pkcs8-der.key', 'test-third-der.crt')]
        for order in (pairs, pairs[::-1]):
            bags = [bag(1, read(key)) for key, _ in order] + [cert_bag(read(cert)) for _, cert in order]
            data = pfx([bags + [cert_bag(read('test-inter-der.crt'))]])
            expected = (order[0][0], order[0][1], [order[1][1], 'test-inter-der.crt'])
            with self.subTest(first=order[0][0]):
                self.assertResult(keys.parse_pkcs12(data, None), expected)

    def test_no_matching_pair(self):
        # Keys and certificates are not matched up, so the first of each is picked
        # even when they do not belong together
        data = pfx([[bag(1, read('test-third-pkcs8-der.key')), bag(1, read('test-pkcs8-der.key')),
                     cert_bag(read('test-inter-der.crt')), cert_bag(read('test-dsa-der.crt'))]])
        expected = ('test-third-pkcs8-der.key', 'test-inter-der.crt', ['test-dsa-der.crt'])
        self.assertResult(keys.parse_pkcs12(data, None), expected)

    def test_ber_outer_layers(self):
        # Changes the encoding around the authenticated safe, which keeps the MAC valid.
        # oscrypto rejects this, since it computes the MAC over the chunk encoding.
        ber = to_ber(read('openssl-default.p12'))
        self.assertIn(b'\x24\x80\x04\x10', ber)
        self.assertResult(keys.parse_pkcs12(ber, PASSWORD), RSA)

    def test_ber_inner_layers(self):
        # Without a MAC, the content of the authenticated safe can be re-encoded too,
        # including the [0] IMPLICIT encrypted content
        _, contents, _ = read_tlv(read('openssl-nomac.p12'))
        version, auth_safe = der_children(contents)
        content_type, content = der_children(read_tlv(auth_safe)[1])
        inner = to_ber(read_tlv(read_tlv(content)[1])[1])
        self.assertIn(b'\xa0\x80\x04\x10', inner)
        ber = to_ber(seq(version, seq(content_type, explicit0(tlv(0x04, inner)))))
        self.assertResult(keys.parse_pkcs12(ber, PASSWORD), RSA)

    def test_ber_key(self):
        # A file in BER can have the key in BER too, in a key bag or encrypted. It comes
        # back as DER, which is what PyCryptodome can read.
        ber_key = to_ber(read('test-pkcs8-der.key'))
        self.assertIn(b'\x24\x80\x04\x10', ber_key)
        for name, key_bag in (('key bag', bag(1, ber_key)), ('shrouded key bag', aes128_key_bag(ber_key))):
            with self.subTest(bag=name):
                self.assertResult(keys.parse_pkcs12(pfx([[key_bag, cert_bag(read('test-der.crt'))]]), PASSWORD), RSA)

    def test_pbes2_key_length(self):
        key = read('test-pkcs8-der.key')
        rc2_40 = seq(oid('1.2.840.113549.3.2'), seq(integer(160), tlv(0x04, IV8)))  # version 160 is 40 bits
        rc2_ciphertext = cbc_encrypt(ARC2, pbkdf2(PASSWORD, 5), IV8, key, effective_keylen=40)
        for name, key_bag, valid in (
            ('AES-128, 16 bytes', aes128_key_bag(key, key_length=16), True),
            ('RC2-40, 5 bytes', bag(2, pbes2(rc2_40, rc2_ciphertext, 5)), True),
            # These would be AES-256, and RC2 with 128 effective key bits instead of 40.
            # OpenSSL rejects them too.
            ('AES-128, 32 bytes', aes128_key_bag(key, key_length=32), False),
            ('RC2-40, 16 bytes', bag(2, pbes2(rc2_40, rc2_ciphertext, 16)), False),
        ):
            data = pfx([[key_bag, cert_bag(read('test-der.crt'))]])
            with self.subTest(key_length=name):
                if valid:
                    self.assertResult(keys.parse_pkcs12(data, PASSWORD), RSA)
                else:
                    with self.assertRaisesRegex(ValueError, 'does not match'):
                        keys.parse_pkcs12(data, PASSWORD)

    def test_rc2_without_version(self):
        # The version is optional. Without it, the key length comes from the PBKDF2
        # parameters, as in oscrypto. OpenSSL rejects these files.
        rc2 = seq(oid('1.2.840.113549.3.2'), seq(tlv(0x04, IV8)))
        ciphertext = cbc_encrypt(ARC2, pbkdf2(PASSWORD, 16), IV8, read('test-pkcs8-der.key'), effective_keylen=128)
        data = pfx([[bag(2, pbes2(rc2, ciphertext, 16)), cert_bag(read('test-der.crt'))]])
        self.assertResult(keys.parse_pkcs12(data, PASSWORD), RSA)

        data = pfx([[bag(2, pbes2(rc2, ciphertext)), cert_bag(read('test-der.crt'))]])
        with self.assertRaisesRegex(ValueError, 'needs a PBKDF2 key length'):
            keys.parse_pkcs12(data, PASSWORD)

    def test_null_password(self):
        # The PKCS#12 key derivation tells an empty password, the NUL terminator of an
        # empty BMPString, from no password at all. OpenSSL reads files made with either,
        # and an empty password has to work for both.
        key, cert = read('test-pkcs8-der.key'), cert_bag(read('test-der.crt'))
        for form, kdf_password in (('empty', b''), ('none', None)):
            # PKCS#12 PBE, the only encryption that depends on the form
            des3_key = pkcs12_kdf('sha1', kdf_password, SALT, ITERATIONS, 24, 1)
            des3_iv = pkcs12_kdf('sha1', kdf_password, SALT, ITERATIONS, 8, 2)
            pkcs12_pbe = seq(seq(oid('1.2.840.113549.1.12.1.3'), seq(tlv(0x04, SALT), integer(ITERATIONS))),
                             tlv(0x04, cbc_encrypt(DES3, des3_key, des3_iv, key)))
            # PKCS#5 PBES1 with SHA-1 and DES, and PBES2, take both forms as an empty password
            derived = SALT
            for _ in range(ITERATIONS):
                derived = hashlib.sha1(derived).digest()
            pbes1 = seq(seq(oid('1.2.840.113549.1.5.10'), seq(tlv(0x04, SALT), integer(ITERATIONS))),
                        tlv(0x04, cbc_encrypt(DES, derived[:8], derived[8:16], key)))
            for name, data in (
                ('PKCS#12 PBE', pfx_with_mac([bag(2, pkcs12_pbe), cert], kdf_password)),
                ('PKCS#12 PBE without MAC', pfx([[bag(2, pkcs12_pbe), cert]])),
                ('PBES1', pfx_with_mac([bag(2, pbes1), cert], kdf_password)),
                ('PBES2', pfx_with_mac([aes128_key_bag(key, b''), cert], kdf_password)),
            ):
                for password in (b'', None):
                    with self.subTest(form=form, file=name, password=password):
                        self.assertResult(keys.parse_pkcs12(data, password), RSA)

    def test_bag_types(self):
        data = pfx([
            [bag(5, seq(oid('1.2.3.4'), explicit0(tlv(0x04, b'secret'))))],  # secret bag, ignored
            [bag(6, seq(bag(1, read('test-pkcs8-der.key')), cert_bag(read('test-der.crt'))))],
            [bag(4, seq(oid('1.2.840.113549.1.9.23.1'), explicit0(tlv(0x04, b'crl'))))],  # CRL bag, ignored
            [bag(3, seq(oid('1.2.840.113549.1.9.22.2'), explicit0(tlv(0x04, b'sdsi'))))],  # non-X.509 cert, ignored
        ])
        self.assertResult(keys.parse_pkcs12(data, None), RSA)

    def test_pbkdf2_prfs(self):
        for prf in ('hmacWithSHA1', 'hmacWithSHA224', 'hmacWithSHA384', 'hmacWithSHA512'):
            with self.subTest(prf=prf):
                data = pfx([[bag(2, read('pkcs8-%s.der' % prf)), cert_bag(read('test-der.crt'))]])
                self.assertResult(keys.parse_pkcs12(data, PASSWORD), RSA)

    def test_wrong_password(self):
        for filename in ('test-tripledes.p12', 'openssl-default.p12', 'openssl-unicode.p12'):
            with self.subTest(filename=filename):
                with self.assertRaisesRegex(ValueError, 'Password provided is invalid'):
                    keys.parse_pkcs12(read(filename), b'wrong')

    def test_wrong_password_without_mac(self):
        with self.assertRaisesRegex(ValueError, 'invalid padding'):
            keys.parse_pkcs12(read('openssl-nomac.p12'), b'wrong')

    def test_argument_types(self):
        with self.assertRaisesRegex(TypeError, 'data must be a byte string'):
            keys.parse_pkcs12(read('openssl-default.p12').decode('latin-1'), PASSWORD)
        with self.assertRaisesRegex(TypeError, 'password must be a byte string'):
            keys.parse_pkcs12(read('openssl-default.p12'), u'password123')

    def test_malformed(self):
        data = read('openssl-default.p12')
        for value in (b'', b'\x30', b'\x30\x03\x02\x01\x03', data[:-40], data[:100], b'\x04\x03abc'):
            with self.subTest(value=value[:8]):
                with self.assertRaises(ValueError):
                    keys.parse_pkcs12(value, PASSWORD)

    def test_deep_nesting(self):
        # Each of these used to hit the recursion limit
        octets = tlv(0x04, b'x')
        bags = cert_bag(read('test-der.crt'))
        for _ in range(1000):
            octets = tlv(0x24, octets)  # BER chunks within chunks
            bags = bag(6, seq(bags))
        for name, value in (
            ('indefinite lengths', b'\x30\x80' * 1000),
            ('OCTET STRING chunks', seq(tlv(0x02, b'\x03'), seq(oid('1.2.840.113549.1.7.1'), explicit0(octets)))),
            ('SafeContents bags', pfx([[bags]])),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, 'nested too deeply'):
                    keys.parse_pkcs12(value, PASSWORD)

    def test_zero_iterations(self):
        data = read('openssl-default.p12')
        self.assertTrue(data.endswith(b'\x02\x02\x08\x00'))  # 2048 MAC iterations
        with self.assertRaisesRegex(ValueError, 'iterations must be greater than 0'):
            keys.parse_pkcs12(data[:-4] + b'\x02\x02\x00\x00', PASSWORD)

    def test_signed_data_auth_safe(self):
        data = read('openssl-default.p12')
        data_oid = oid('1.2.840.113549.1.7.1')
        signed = data.replace(data_oid, oid('1.2.840.113549.1.7.2'), 1)
        with self.assertRaisesRegex(ValueError, 'Only password-protected PKCS12 files'):
            keys.parse_pkcs12(signed, PASSWORD)

    def test_enveloped_data_content(self):
        data = read('openssl-nomac.p12')
        enveloped = data.replace(oid('1.2.840.113549.1.7.6'), oid('1.2.840.113549.1.7.3'), 1)
        with self.assertRaisesRegex(ValueError, 'Public-key-based PKCS12 files'):
            keys.parse_pkcs12(enveloped, PASSWORD)

    def test_unsupported(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported PKCS12 MAC algorithm'):
            keys.parse_pkcs12(read('openssl-pbmac1.p12'), PASSWORD)

    def test_other_key_algorithms(self):
        # Keys and certificates are returned as they are, whatever their algorithm.
        # oscrypto fails on both of these files.
        key, cert, extra = keys.parse_pkcs12(read('openssl-ed25519.p12'), PASSWORD)
        self.assertEqual(read_pem('ed25519.key'), key.dump())
        self.assertEqual(read_pem('ed25519.crt'), cert.dump())
        self.assertEqual([], extra)

        # An EC key stored without its public key, as Java writes them
        key, cert, extra = keys.parse_pkcs12(read('openssl-ec-nopub.p12'), PASSWORD)
        self.assertIsInstance(key, keys.PrivateKeyInfo)
        self.assertEqual(read('ec-prime256v1-der.crt'), cert.dump())
        self.assertEqual([], extra)


class DumpTests(TestCase):

    def setUp(self):
        self.key, self.cert, _ = keys.parse_pkcs12(read('openssl-default.p12'), PASSWORD)

    def test_dump_certificate(self):
        self.assertEqual(read('test-der.crt'), self.cert.dump())

    def test_dump_private_key(self):
        self.assertEqual(read('test-pkcs8-der.key'), self.key.dump())


if __name__ == '__main__':
    unittest.main()
