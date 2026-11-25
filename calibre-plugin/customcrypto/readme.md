# customcrypto

A subset of [oscrypto](https://github.com/wbond/oscrypto) and
[asn1crypto](https://github.com/wbond/asn1crypto) to handle Adobe's PKCS12 files.
The ciphers come from [PyCryptodome](https://www.pycryptodome.org), imported as
`Cryptodome` or `Crypto`, or from PyCrypto 2.6, which Calibre 3 bundles.


```python
from customcrypto import keys

privkey, cert, _ = keys.parse_pkcs12(mock_p12_data, mock_p12_password)
cert = cert.dump()
privkey = privkey.dump()
```


## What is left

Supported encryption is the same set oscrypto handles:

- PBES2 with PBKDF2 (HMAC-SHA1/224/256/384/512) and AES-128/192/256-CBC,
  DES-CBC, DES-EDE3-CBC or RC2-CBC. This is the OpenSSL 3, Java and modern Windows default.
- PKCS#12 PBE with SHA-1 and 3DES, 2-key 3DES, RC2-40/128 or RC4-40/128. This
  is the OpenSSL 1.x and older Windows default.
- PKCS#5 PBES1 with MD5 or SHA-1 and DES or RC2-64
- MACs with SHA-1/224/256/384/512, or no MAC

`parse_pkcs12()` returns the first private key and the first certificate in the
file, plus the other certificates. They come back as they are, whatever their
algorithm. Keys and certificates are not matched up, since the files this is
for have one of each.

## Tests

```bash
python -m unittest discover -s tests -t .
```

`tests/fixtures/generate.sh` documents how the OpenSSL fixtures were created.
The `test-*` fixtures come from the oscrypto test suite.
