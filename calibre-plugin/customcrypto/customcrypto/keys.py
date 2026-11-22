"""
PKCS#12 parsing, reduced from oscrypto._asymmetric._parse_pkcs12 and the
asn1crypto pkcs12, cms, keys and algos structures it relies on.
"""

import binascii
import hashlib
import hmac
from collections import OrderedDict

from . import _asn1
from ._cipher import decrypt
from ._kdf import pbkdf1, pkcs12_kdf

__all__ = [
    'Certificate',
    'parse_pkcs12',
    'PrivateKeyInfo',
]


class _Der(object):
    """An encoded ASN.1 structure, kept as the exact bytes found in the PKCS#12 file"""

    def __init__(self, der):
        self._der = der

    def dump(self):
        return self._der

    def __repr__(self):
        return '<%s %d bytes>' % (type(self).__name__, len(self._der))


class Certificate(_Der):
    """A DER-encoded X.509 certificate"""


class PrivateKeyInfo(_Der):
    """A DER-encoded, unencrypted PKCS#8 PrivateKeyInfo"""


_DATA = '1.2.840.113549.1.7.1'
_ENCRYPTED_DATA = '1.2.840.113549.1.7.6'

_KEY_BAG = '1.2.840.113549.1.12.10.1.1'
_PKCS8_SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2'
_CERT_BAG = '1.2.840.113549.1.12.10.1.3'
_SAFE_CONTENTS_BAG = '1.2.840.113549.1.12.10.1.6'
_X509_CERT = '1.2.840.113549.1.9.22.1'

_RSA = '1.2.840.113549.1.1.1'
_DSA = '1.2.840.10040.4.1'
_EC = '1.2.840.10045.2.1'

# asn1crypto names, used in the EC fingerprint. Other curves use the dotted OID,
# which only changes the order oscrypto would pick among several matching keys.
_CURVE_NAMES = {
    '1.2.840.10045.3.1.7': 'secp256r1',
    '1.3.132.0.34': 'secp384r1',
    '1.3.132.0.35': 'secp521r1',
}

_MAC_DIGESTS = {
    '1.3.14.3.2.26': 'sha1',
    '2.16.840.1.101.3.4.2.4': 'sha224',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
}

# PKCS#12 appendix C: OID -> (cipher, key length)
_PKCS12_PBE = {
    '1.2.840.113549.1.12.1.1': ('rc4', 16),
    '1.2.840.113549.1.12.1.2': ('rc4', 5),
    '1.2.840.113549.1.12.1.3': ('tripledes', 24),
    '1.2.840.113549.1.12.1.4': ('tripledes', 16),
    '1.2.840.113549.1.12.1.5': ('rc2', 16),
    '1.2.840.113549.1.12.1.6': ('rc2', 5),
}

# PKCS#5 PBES1: OID -> (hash, cipher). The MD2 variants are left out since
# hashlib has no MD2.
_PBES1 = {
    '1.2.840.113549.1.5.3': ('md5', 'des'),
    '1.2.840.113549.1.5.6': ('md5', 'rc2'),
    '1.2.840.113549.1.5.10': ('sha1', 'des'),
    '1.2.840.113549.1.5.11': ('sha1', 'rc2'),
}

_PBES2 = '1.2.840.113549.1.5.13'
_PBKDF2 = '1.2.840.113549.1.5.12'

_PBKDF2_PRFS = {
    '1.2.840.113549.2.7': 'sha1',
    '1.2.840.113549.2.8': 'sha224',
    '1.2.840.113549.2.9': 'sha256',
    '1.2.840.113549.2.10': 'sha384',
    '1.2.840.113549.2.11': 'sha512',
}

# PBES2 encryption schemes: OID -> (cipher, key length)
_PBES2_SCHEMES = {
    '1.3.14.3.2.7': ('des', 8),
    '1.2.840.113549.3.7': ('tripledes', 24),
    '1.2.840.113549.3.2': ('rc2', None),
    '2.16.840.1.101.3.4.1.2': ('aes', 16),
    '2.16.840.1.101.3.4.1.22': ('aes', 24),
    '2.16.840.1.101.3.4.1.42': ('aes', 32),
}

# RFC 8018 B.2.3: RC2 parameter version -> key length in bytes
_RC2_VERSIONS = {160: 5, 120: 8, 58: 16}


def parse_pkcs12(data, password=None):
    """
    Parses a PKCS#12 ASN.1 DER-encoded structure and extracts certs and keys

    :param data:
        A byte string of a DER-encoded PKCS#12 file

    :param password:
        A byte string of the password to any encrypted data

    :raises:
        ValueError - when any of the parameters are of the wrong value, or the
                     file is malformed or uses an unsupported feature
        TypeError - when any of the parameters are of the wrong type

    :return:
        A three-element tuple of:
         1. A PrivateKeyInfo object, or None
         2. A Certificate object, or None
         3. A list of zero or more Certificate objects that are "extra"
            certificates, possibly intermediates from the cert chain
    """

    if not isinstance(data, bytes):
        raise TypeError('data must be a byte string, not %s' % type(data).__name__)
    if password is None:
        password = b''
    elif not isinstance(password, bytes):
        raise TypeError('password must be a byte string, not %s' % type(password).__name__)

    pfx = _asn1.load(data).seq(2)
    auth_safe = pfx[1].seq(2)
    if auth_safe[0].oid() != _DATA:
        raise ValueError('Only password-protected PKCS12 files are currently supported')
    auth_safe_content = auth_safe[1].explicit(0).octets()

    if len(pfx) > 2:
        _verify_mac(pfx[2], auth_safe_content, password)

    certs = OrderedDict()  # file order, which plain dicts only keep from Python 3.7
    private_keys = {}

    for content_info in _asn1.load(auth_safe_content).seq():
        content_info = content_info.seq(2)
        content_type, content = content_info[0].oid(), content_info[1].explicit(0)
        if content_type == _DATA:
            safe_contents = content.octets()
        elif content_type == _ENCRYPTED_DATA:
            encrypted_content_info = content.seq(2)[1].seq(3)
            if not encrypted_content_info[2].is_context(0):
                raise ValueError('PKCS12 encrypted data is missing its content')
            safe_contents = _decrypt(encrypted_content_info[1], encrypted_content_info[2].octets(), password)
        else:
            raise ValueError('Public-key-based PKCS12 files are not currently supported')
        _parse_safe_contents(_asn1.load(safe_contents), certs, private_keys, password)

    # Same choice as oscrypto: the key and certificate with the lowest common
    # fingerprint, or else the lowest of each. The extra certificates stay in
    # file order, where oscrypto sorts them by subject if nothing matched.
    common = set(private_keys) & set(certs)
    key = private_keys[min(common or private_keys)] if private_keys else None
    cert = certs.pop(min(common or certs)) if certs else None
    return (key, cert, list(certs.values()))


def _verify_mac(mac_data, content, password):
    mac_data = mac_data.seq(2)
    digest_info = mac_data[0].seq(2)
    digest_oid = _algorithm(digest_info[0])[0]
    if digest_oid not in _MAC_DIGESTS:
        raise ValueError('Unsupported PKCS12 MAC algorithm %s' % digest_oid)
    digest = _MAC_DIGESTS[digest_oid]
    salt = mac_data[1].octets()
    iterations = mac_data[2].int() if len(mac_data) > 2 else 1

    # ID 3 is for generating an HMAC key
    mac_key = pkcs12_kdf(digest, password, salt, iterations, hashlib.new(digest).digest_size, 3)
    computed_hmac = hmac.new(mac_key, content, getattr(hashlib, digest)).digest()
    if not hmac.compare_digest(computed_hmac, digest_info[1].octets()):
        raise ValueError('Password provided is invalid')


def _parse_safe_contents(safe_contents, certs, private_keys, password):
    for safe_bag in safe_contents.seq():
        safe_bag = safe_bag.seq(2)
        bag_id = safe_bag[0].oid()
        bag_value = safe_bag[1].explicit(0)

        if bag_id == _CERT_BAG:
            cert_bag = bag_value.seq(2)
            if cert_bag[0].oid() == _X509_CERT:
                cert = _asn1.load(cert_bag[1].explicit(0).octets())
                certs[_cert_fingerprint(cert)] = Certificate(cert.raw)

        elif bag_id == _KEY_BAG:
            private_keys[_key_fingerprint(bag_value)] = PrivateKeyInfo(bag_value.raw)

        elif bag_id == _PKCS8_SHROUDED_KEY_BAG:
            encrypted_key_info = bag_value.seq(2)
            key = _asn1.load(_decrypt(encrypted_key_info[0], encrypted_key_info[1].octets(), password))
            private_keys[_key_fingerprint(key)] = PrivateKeyInfo(key.raw)

        elif bag_id == _SAFE_CONTENTS_BAG:
            _parse_safe_contents(bag_value, certs, private_keys, password)

        # CRL bags and secret bags are ignored


def _decrypt(algorithm, data, password):
    """
    Decrypts PKCS#12 or PKCS#5 password-encrypted data

    :param algorithm:
        The AlgorithmIdentifier element describing the encryption

    :return:
        A byte string of the plaintext
    """

    oid, params = _algorithm(algorithm)
    if oid not in _PKCS12_PBE and oid not in _PBES1 and oid != _PBES2:
        raise ValueError('Unsupported encryption algorithm %s' % oid)
    if params is None:
        raise ValueError('Encryption algorithm %s is missing its parameters' % oid)

    if oid != _PBES2:
        params = params.seq(2)
        salt, iterations = params[0].octets(), params[1].int()
        if oid in _PKCS12_PBE:
            cipher, key_length = _PKCS12_PBE[oid]
            key = pkcs12_kdf('sha1', password, salt, iterations, key_length, 1)
            # Since RC4 is a stream cipher, it does not use an IV
            iv = None if cipher == 'rc4' else pkcs12_kdf('sha1', password, salt, iterations, 8, 2)
        else:
            hash_algorithm, cipher = _PBES1[oid]
            derived = pbkdf1(hash_algorithm, password, salt, iterations, 16)
            key, iv = derived[:8], derived[8:]
        return decrypt(cipher, key, data, iv)

    kdf, scheme = params.seq(2)[:2]
    kdf_oid, kdf_params = _algorithm(kdf)
    if kdf_oid != _PBKDF2 or kdf_params is None:
        raise ValueError('Unsupported PBES2 key derivation function %s' % kdf_oid)
    kdf_params = kdf_params.seq(2)
    salt, iterations = kdf_params[0].octets(), kdf_params[1].int()
    key_length, prf = None, 'sha1'
    for field in kdf_params[2:]:  # the optional keyLength INTEGER and prf AlgorithmIdentifier
        if field.constructed:
            prf_oid = _algorithm(field)[0]
            if prf_oid not in _PBKDF2_PRFS:
                raise ValueError('Unsupported PBKDF2 PRF %s' % prf_oid)
            prf = _PBKDF2_PRFS[prf_oid]
        else:
            key_length = field.int()

    scheme_oid, scheme_params = _algorithm(scheme)
    if scheme_oid not in _PBES2_SCHEMES or scheme_params is None:
        raise ValueError('Unsupported PBES2 encryption scheme %s' % scheme_oid)
    cipher, scheme_key_length = _PBES2_SCHEMES[scheme_oid]
    if cipher == 'rc2':
        rc2_params = scheme_params.seq(1)  # the optional version, then the IV
        version = rc2_params[0].int() if len(rc2_params) > 1 else None
        if version not in _RC2_VERSIONS:
            raise ValueError('Unsupported RC2 parameter version %s' % version)
        scheme_key_length = _RC2_VERSIONS[version]
        iv = rc2_params[-1].octets()
    else:
        iv = scheme_params.octets()

    key = hashlib.pbkdf2_hmac(prf, password, salt, iterations, key_length or scheme_key_length)
    return decrypt(cipher, key, data, iv)


def _algorithm(algorithm_identifier):
    """Returns the OID and the parameters (None when absent) of an AlgorithmIdentifier"""
    fields = algorithm_identifier.seq(1)
    return fields[0].oid(), (fields[1] if len(fields) > 1 else None)


def _dsa_params(params):
    if params is None:
        raise ValueError('DSA key is missing its p, q and g parameters')
    return [value.int() for value in params.seq(3)[:3]]


def _curve(params):
    if params is not None and params.cls == 0 and params.tag == 6:
        oid = params.oid()
        return _CURVE_NAMES.get(oid, oid).encode('ascii')
    # Specified or implicit curves - only needs to be consistent between key and cert
    return binascii.hexlify(params.raw if params is not None else b'')


def _fingerprint(algorithm, params, public_key):
    """
    The same correlation hash as oscrypto._asymmetric._fingerprint

    :param public_key:
        For RSA a (modulus, exponent) tuple, for DSA the public integer and
        for EC the encoded point
    """

    if algorithm == _RSA:
        to_hash = ('%d:%d' % public_key).encode('ascii')
    elif algorithm == _DSA:
        to_hash = ('%d:%d:%d:%d' % tuple(_dsa_params(params) + [public_key])).encode('ascii')
    else:
        to_hash = _curve(params) + b':' + public_key
    return hashlib.sha256(to_hash).digest()


def _key_fingerprint(private_key_info):
    fields = private_key_info.seq(3)
    algorithm, params = _algorithm(fields[1])
    private_key = _asn1.load(fields[2].octets())

    if algorithm == _RSA:
        rsa = private_key.seq(3)
        return _fingerprint(algorithm, params, (rsa[1].int(), rsa[2].int()))

    if algorithm == _DSA:
        p, _, g = _dsa_params(params)
        return _fingerprint(algorithm, params, pow(g, private_key.int(), p))

    if algorithm == _EC:
        for field in private_key.seq(2)[2:]:
            if field.is_context(1):
                return _fingerprint(algorithm, params, field.explicit(1).bits())
        # oscrypto fails on these too
        raise ValueError('EC private keys without an embedded public key are not supported')

    raise ValueError('Unsupported private key algorithm %s' % algorithm)


def _cert_fingerprint(certificate):
    fields = certificate.seq(1)[0].seq(6)
    if fields[0].is_context(0):  # explicit version field
        fields = fields[1:]
    if len(fields) < 6:
        raise ValueError('Invalid X.509 certificate')
    public_key_info = fields[5].seq(2)
    algorithm, params = _algorithm(public_key_info[0])
    public_key = public_key_info[1].bits()

    if algorithm == _RSA:
        rsa = _asn1.load(public_key).seq(2)
        return _fingerprint(algorithm, params, (rsa[0].int(), rsa[1].int()))
    if algorithm == _DSA:
        return _fingerprint(algorithm, params, _asn1.load(public_key).int())
    if algorithm == _EC:
        return _fingerprint(algorithm, params, public_key)
    raise ValueError('Unsupported certificate public key algorithm %s' % algorithm)
