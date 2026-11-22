"""
A pure-Python subset of oscrypto (and asn1crypto) that reads the private key
and certificates out of a password-protected PKCS#12 (.p12/.pfx) file:

    from customcrypto import keys
    from customcrypto.asymmetric import dump_certificate, dump_private_key

    privkey, cert, _ = keys.parse_pkcs12(p12_data, p12_password)
    cert = dump_certificate(cert, encoding="der")
    privkey = dump_private_key(privkey, None, "der")
"""

__version__ = '0.0.1'
