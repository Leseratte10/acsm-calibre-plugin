# customcrypto

A pure-Python subset of [oscrypto](https://github.com/wbond/oscrypto) and
[asn1crypto](https://github.com/wbond/asn1crypto) to handle Adobe's PKCS12 files.


```python
from customcrypto import keys
from customcrypto.asymmetric import dump_certificate, dump_private_key

privkey, cert, _ = keys.parse_pkcs12(mock_p12_data, mock_p12_password)
cert = dump_certificate(cert, encoding="der")
privkey = dump_private_key(privkey, None, "der")
```

This is the same code as with oscrypto, apart from the package name in the imports.

## What is left

Supported encryption is the same set oscrypto handles:

- PBES2 with PBKDF2 (HMAC-SHA1/224/256/384/512) and AES-128/192/256-CBC,
  DES-CBC, DES-EDE3-CBC or RC2-CBC. This is the OpenSSL 3, Java and modern Windows default.
- PKCS#12 PBE with SHA-1 and 3DES, 2-key 3DES, RC2-40/128 or RC4-40/128. This
  is the OpenSSL 1.x and older Windows default.
- PKCS#5 PBES1 with MD5 or SHA-1 and DES or RC2-64
- MACs with SHA-1/224/256/384/512, or no MAC

Supported key types are RSA, DSA and EC.

## Tests

```bash
python -m unittest discover -s tests -t .
```

`tests/fixtures/generate.sh` documents how the OpenSSL fixtures were created.
The `test-*` fixtures come from the oscrypto test suite.
