"""
The two serialization functions from oscrypto.asymmetric, limited to DER
output and unencrypted private keys.
"""

from .keys import Certificate, PrivateKeyInfo

__all__ = [
    'dump_certificate',
    'dump_private_key',
]


def dump_certificate(certificate, encoding):
    """
    Serializes a certificate object into a byte string

    :param certificate:
        A customcrypto.keys.Certificate object

    :param encoding:
        Must be "der"

    :return:
        A byte string of the DER-encoded certificate
    """

    if encoding != 'der':
        raise ValueError('encoding must be "der", not %r' % (encoding,))
    if not isinstance(certificate, Certificate):
        raise TypeError('certificate must be an instance of customcrypto.keys.Certificate, not %s'
                        % type(certificate).__name__)
    return certificate.dump()


def dump_private_key(private_key, passphrase, encoding):
    """
    Serializes a private key object into a byte string of the PKCS#8 format

    :param private_key:
        A customcrypto.keys.PrivateKeyInfo object

    :param passphrase:
        Must be None, encrypting the output is not supported

    :param encoding:
        Must be "der"

    :return:
        A byte string of the DER-encoded, unencrypted PKCS#8 private key
    """

    if encoding != 'der':
        raise ValueError('encoding must be "der", not %r' % (encoding,))
    if passphrase is not None:
        raise ValueError('passphrase must be None, encrypting private keys is not supported')
    if not isinstance(private_key, PrivateKeyInfo):
        raise TypeError('private_key must be an instance of customcrypto.keys.PrivateKeyInfo, not %s'
                        % type(private_key).__name__)
    return private_key.dump()
