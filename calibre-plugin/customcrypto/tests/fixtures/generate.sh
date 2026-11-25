#!/bin/sh
# Regenerates the openssl-*.p12 fixtures.
#
# The test-*.p12 files and the RSA/DSA test keys and certificates are copied
# from the oscrypto test suite. EC keys are only generated when missing,
# so existing expected outputs stay valid.
#
# Requires OpenSSL 3.4+ (for PBMAC1, with the legacy provider for DES/RC2/RC4).

set -e
cd "$(dirname "$0")"

PASS=password123
OSSL="-provider legacy -provider default"

p12() {
    out=$1
    shift
    openssl pkcs12 -export $OSSL -out "$out" "$@"
}

rsa() {
    out=$1
    shift
    p12 "$out" -inkey test.key -in test.crt -passout pass:$PASS "$@"
}

openssl pkcs8 -topk8 -nocrypt -outform DER -in test-third.key -out test-third-pkcs8-der.key

# Ciphers - each file covers one algorithm for the key and another for the certificate
rsa openssl-default.p12
rsa openssl-aes128-aes192.p12 -keypbe AES-128-CBC -certpbe AES-192-CBC
rsa openssl-des3-des.p12 -keypbe DES-EDE3-CBC -certpbe DES-CBC
rsa openssl-rc2-rc2-40.p12 -keypbe RC2-CBC -certpbe RC2-40-CBC
rsa openssl-rc2-64-none.p12 -keypbe RC2-64-CBC -certpbe NONE
rsa openssl-md5-des-sha1-rc2-64.p12 -keypbe PBE-MD5-DES -certpbe PBE-SHA1-RC2-64
rsa openssl-sha1-des-md5-rc2-64.p12 -keypbe PBE-SHA1-DES -certpbe PBE-MD5-RC2-64
rsa openssl-rc4-128-rc4-40.p12 -keypbe PBE-SHA1-RC4-128 -certpbe PBE-SHA1-RC4-40
rsa openssl-2des-rc2-128.p12 -keypbe PBE-SHA1-2DES -certpbe PBE-SHA1-RC2-128

# MAC and iteration variants
rsa openssl-none-sha512mac.p12 -keypbe NONE -certpbe NONE -macalg sha512
rsa openssl-sha224mac.p12 -macalg sha224
rsa openssl-sha384mac.p12 -macalg sha384
rsa openssl-nomac.p12 -nomac -certpbe AES-256-CBC
rsa openssl-noiter.p12 -noiter -nomaciter
rsa openssl-pbmac1.p12 -pbmac1_pbkdf2

# PBKDF2 PRF variants, as encrypted PKCS#8 that the tests wrap in a PKCS#12
# structure (hmacWithSHA1 is the DEFAULT, so OpenSSL omits the prf field)
for prf in hmacWithSHA1 hmacWithSHA224 hmacWithSHA384 hmacWithSHA512; do
    openssl pkcs8 -topk8 $OSSL -v2 aes-128-cbc -v2prf $prf -in test.key -outform DER -out pkcs8-$prf.der -passout pass:$PASS
done

# Passwords
p12 openssl-unicode.p12 -inkey test.key -in test.crt -passout 'pass:pässwörd€'
p12 openssl-unicode-legacy.p12 -legacy -inkey test.key -in test.crt -passout 'pass:pässwörd€'
p12 openssl-blank.p12 -inkey test.key -in test.crt -passout pass:

# Chains and certificate selection
cat test-inter.crt test.crt > chain.tmp
p12 openssl-chain.p12 -inkey test-third.key -in test-third.crt -certfile chain.tmp -passout pass:$PASS
cat test-third.crt test-inter.crt test.crt > chain.tmp
p12 openssl-certs-only.p12 -nokeys -in chain.tmp -passout pass:$PASS
rm chain.tmp

# Other key types
for curve in prime256v1 secp384r1 secp521r1; do
    if [ ! -f ec-$curve.key ]; then
        openssl ecparam -name $curve -genkey -noout -out ec-$curve.key
        openssl req -x509 -new -key ec-$curve.key -subj "/CN=$curve" -days 36500 -out ec-$curve.crt
    fi
    openssl pkcs8 -topk8 -nocrypt -outform DER -in ec-$curve.key -out ec-$curve-pkcs8-der.key
    openssl x509 -in ec-$curve.crt -outform DER -out ec-$curve-der.crt
    # An RSA certificate is added, which has to come back as an extra certificate
    p12 openssl-ec-$curve.p12 -inkey ec-$curve.key -in ec-$curve.crt -certfile test.crt -passout pass:$PASS
done
openssl ec -in ec-prime256v1.key -no_public -out ec-nopub.tmp 2>/dev/null
p12 openssl-ec-nopub.p12 -inkey ec-nopub.tmp -in ec-prime256v1.crt -passout pass:$PASS
rm ec-nopub.tmp

if [ ! -f ed25519.key ]; then
    openssl genpkey -algorithm ed25519 -out ed25519.key
    openssl req -x509 -new -key ed25519.key -subj "/CN=ed25519" -days 36500 -out ed25519.crt
fi
p12 openssl-ed25519.p12 -inkey ed25519.key -in ed25519.crt -passout pass:$PASS

