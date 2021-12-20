#!/usr/bin/python3 

import sys, os
sys.path.append("../calibre-plugin")


import unittest
import base64
from freezegun import freeze_time
from unittest.mock import patch
from lxml import etree


try: 
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_v1_5
except ImportError:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

import libadobe             # type: ignore
import libadobeAccount      # type: ignore
from getEncryptionKeyLinux import unfuck as fix_wine_username # type: ignore
from libpdf import trim_encrypt_string, cleanup_encrypt_element, deflate_and_base64_encode  # type: ignore
from customRSA import CustomRSA # type: ignore


class TestAdobe(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")


    def test_checkIfVersionListsAreValid(self):
        '''
        Check if version lists are sane

        These four lists must all have the same amount of elements. 
        Also, the default build ID must be valid, and all the IDs 
        available for authorization or switching must be valid, too.
        '''

        self.assertIn(libadobe.VAR_VER_DEFAULT_BUILD_ID, libadobe.VAR_VER_BUILD_IDS, "Default build ID invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_SUPP_VERSIONS),   "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_HOBBES_VERSIONS), "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_OS_IDENTIFIERS),  "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_BUILD_IDS),       "Version lists seem to be invalid")

        for version in libadobe.VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
            self.assertIn(version, libadobe.VAR_VER_BUILD_IDS, "Invalid buildID for authorization")
        for version in libadobe.VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO:
            self.assertIn(version, libadobe.VAR_VER_BUILD_IDS, "Invalid buildID for switching")

    def test_serialGeneration(self):
        '''Check if serial generation works'''
        self.assertEqual((len(libadobe.get_mac_address())), 6,  "MAC address invalid")
        self.assertEqual(libadobe.get_mac_address(), libadobe.get_mac_address(), "MAC address not constant")
        self.assertEqual((len(libadobe.makeSerial(False))), 40, "SHA1 hash for device serial invalid (device-based)")
        self.assertEqual((len(libadobe.makeSerial(True))), 40,  "SHA1 hash for device serial invalid (random)")
        self.assertEqual(libadobe.makeSerial(False), libadobe.makeSerial(False), "Two non-random serials not identical")

    def test_fingerprintGeneration(self): 
        '''Check if fingerprint generation works'''
        libadobe.devkey_bytes = bytes([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        self.assertEqual(libadobe.makeFingerprint("f0081bce3f771bdeeb26fcb4b2011fed77edff7b"), b"FgLMNXxv1BZPqMOM6IUnfaG4Qj8=", "Wrong fingerprint")
        self.assertEqual(libadobe.makeFingerprint("HelloWorld123"),                            b"hpp223C1kfLDOoyxo8WR7KhcXB8=", "Wrong fingerprint")


    @patch("libadobe.Random")
    def test_deviceKeyEncryption(self, random):
        '''Check if encryption with the device key works'''

        # Overwrite the get_random_bytes function that's used to get a random IV
        # Forcing hard-coded IV ...
        random.get_random_bytes._mock_side_effect = lambda rndlen: bytes([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 
                                                                          0xae, 0xc8, 0x70, 0xd4, 0x46, 0x6c, 0x8b, 0xb0])


        libadobe.devkey_bytes = bytes([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])
        mock_data = b"Test message"
        mock_result = libadobe.encrypt_with_device_key(mock_data)
        expected_result = bytes([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 0xae, 0xc8, 0x70, 0xd4,
                                 0x46, 0x6c, 0x8b, 0xb0, 0x23, 0x5a, 0xd3, 0x1b, 0x4e, 0x2b, 0x12, 0x79,
                                 0x85, 0x63, 0x2d, 0x01, 0xa4, 0xe8, 0x29, 0x22])
        
        self.assertEqual(mock_result, expected_result, "devkey encryption returned invalid result")

    def test_deviceKeyDecryption(self):
        '''Check if decryption with the device key works'''

        libadobe.devkey_bytes = bytes([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        mock_data = bytes([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 0xae, 0xc8, 0x70, 0xd4,
                           0x46, 0x6c, 0x8b, 0xb0, 0x23, 0x5a, 0xd3, 0x1b, 0x4e, 0x2b, 0x12, 0x79,
                           0x85, 0x63, 0x2d, 0x01, 0xa4, 0xe8, 0x29, 0x22])

        mock_result = libadobe.decrypt_with_device_key(mock_data)
        expected_result = b"Test message"

        self.assertEqual(mock_result, expected_result, "devkey decryption returned invalid result")

    @freeze_time("2021-12-18 22:07:15.988961")
    def test_verifyNonceCalculation(self): 
        '''Check if the nonce calculation is correct, at a given date/time'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>8B2aPgg6AAAAAAAA</adept:nonce><adept:expiration>2021-12-18T22:17:15Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2021")

    
    @freeze_time("2031-07-19 22:15:22.074860")
    def test_verifyNonceCalculationFuture(self): 
        '''Check if the nonce calculation is still correct in the future'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>JFUTp046AAAAAAAA</adept:nonce><adept:expiration>2031-07-19T22:25:22Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2031")


    
    def test_hash_node(self): 
        '''Check if the XML hash (needed for the signature) is correct'''

        # This XML is an anonymized (all IDs replaced with random UUIDs) ACSM file.

        mock_xml_str = """
                <fulfillmentToken fulfillmentType="free" auth="user" xmlns="http://ns.adobe.com/adept">
                <distributor>urn:uuid:6f633050-ac85-48e7-9204-831bd44db21b</distributor>
                <operatorURL>https://example.com/fulfillment</operatorURL>
                <transaction>351f9325-da50-492a-ab56-f1adc995ce1c-00000001</transaction>
                <expiration>2021-12-18T21:26:05+00:00</expiration>
                <resourceItemInfo>
                    <resource>urn:uuid:6f300313-d746-44b6-8c88-5b2afa8e0909</resource>
                    <resourceItem>1</resourceItem>
                    <metadata>
                    <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Book title</dc:title>
                    <dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">Book author</dc:creator>
                    <dc:publisher xmlns:dc="http://purl.org/dc/elements/1.1/">Book publisher</dc:publisher>
                    <dc:identifier xmlns:dc="http://purl.org/dc/elements/1.1/">Book identifier</dc:identifier>
                    <dc:format xmlns:dc="http://purl.org/dc/elements/1.1/">application/epub+zip</dc:format>
                    <dc:language xmlns:dc="http://purl.org/dc/elements/1.1/">en-us</dc:language>
                    </metadata>
                    <licenseToken>
                    <resource>urn:uuid:fca00d01-4eaf-4c70-b00c-1caa9a71f5be</resource>
                    <permissions>
                        <display/>
                        <excerpt/>
                        <print/>
                        <play/>
                    </permissions>
                    </licenseToken>
                </resourceItemInfo>
                <hmac>fHv+2R4N61aP6d0S8/g+RRHEGPE=</hmac>
                </fulfillmentToken>
        """

        mock_xml_obj = etree.fromstring(mock_xml_str)
        sha_hash = libadobe.hash_node(mock_xml_obj).hexdigest().lower()

        self.assertEqual(sha_hash, "3452e3d11cdd70eb90323f291c06afafe10e098a", "Invalid SHA hash for node signing")


    def test_sign_node_old(self):

        '''Check if the external RSA library (unused) signs correctly'''

        # This is no longer in use by the plugin, but I still want to leave this test in,
        # in case we need to go back to the old method.

        mock_signing_key = "MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBALluuPvdDpr4L0j3eIGy3VxhgRcEKU3++qwbdvLXI99/izW9kfELFFJtq5d4ktIIUIvHsWkW0jblGi+bQ4sQXCeIvtOgqVHMSvRpW78lnGEkdD4Y1qhbcVGw7OGpWlhp8qCJKVCGbrkML7BSwFvQqqvg4vMU8O1uALfJvicKN3YfAgMBAAECf3uEg+Hr+DrstHhZF40zJPHKG3FkFd3HerXbOawMH5Q6CKTuKDGmOYQD+StFIlMArQJh8fxTVM3gSqgPkyyiesw0OuECU985FaLbUWxuCQzBcitnhl+VSv19oEPHTJWu0nYabasfT4oPjf8eiWR/ymJ9DZrjMWWy4Xf/S+/nFYUCQQDIZ1pc9nZsCB4QiBl5agTXoMcKavxFHPKxI/mHfRCHYjNyirziBJ+Dc/N40zKvldNBjO43KjLhUZs/BxdAJo09AkEA7OAdsg6SmviVV8xk0vuTmgLxhD7aZ9vpV4KF5+TH2DbximFoOP3YRObXV862wAjCpa84v43ok7Imtsu3NKQ+iwJAc0mx3GUU/1U0JoKFVSm+m2Ws27tsYT4kB/AQLvetuJSv0CcsPkI2meLsoAev0v84Ry+SIz4tgx31V672mzsSaQJBAJET1rw2Vq5Zr8Y9ZkceVFGQmfGAOW5A71Jsm6zin0+anyc874NwXaQdqiiab61/8A9gGSahOKA1DacJcCTqr28CQGm4mn3rOQFf+nniajIobATjNHaZJ76Xnc6rtoreK6+ZjO9wYF+797X/bhiV11Fpakvyrz6+t7bAd0PPQ2taTDg="
        payload_bytes = bytes([0x34, 0x52, 0xe3, 0xd1, 0x1c, 0xdd, 0x70, 0xeb, 0x90, 0x32, 0x3f, 0x29, 0x1c, 0x06, 0xaf, 0xaf, 0xe1, 0x0e, 0x09, 0x8a])
        
        try: 
            import rsa
        except: 
            return self.skipTest("rsa not installed")

        key = rsa.PrivateKey.load_pkcs1(RSA.importKey(base64.b64decode(mock_signing_key)).exportKey())
        keylen = rsa.pkcs1.common.byte_size(key.n)
        padded = rsa.pkcs1._pad_for_signing(payload_bytes, keylen)
        payload = rsa.pkcs1.transform.bytes2int(padded)
        encrypted = key.blinded_encrypt(payload)
        block = rsa.pkcs1.transform.int2bytes(encrypted, keylen)
        signature = base64.b64encode(block).decode()

        expected_signature = "RO/JmWrustzT50GB9bSb4VdRZCP77y0ZuFFmn8gk/p0E6EbQnqP10QkB5HM8JSV9lKaKJuZpDBJ8cp+FxZmMSPe6odTUiL134Y6tXOCllBtKwVamQjsYbIFLv/HOX68rUadSHpr4QKMle2jeQinIT0viS5kwO7XofKHaSLM2XjE="

        self.assertEqual(signature, expected_signature, "Old (external RSA) node hash signing method broken")


    def test_sign_node_new(self):

        '''Check if the builtin CustomRSA library signs correctly'''

        mock_signing_key = "MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBALluuPvdDpr4L0j3eIGy3VxhgRcEKU3++qwbdvLXI99/izW9kfELFFJtq5d4ktIIUIvHsWkW0jblGi+bQ4sQXCeIvtOgqVHMSvRpW78lnGEkdD4Y1qhbcVGw7OGpWlhp8qCJKVCGbrkML7BSwFvQqqvg4vMU8O1uALfJvicKN3YfAgMBAAECf3uEg+Hr+DrstHhZF40zJPHKG3FkFd3HerXbOawMH5Q6CKTuKDGmOYQD+StFIlMArQJh8fxTVM3gSqgPkyyiesw0OuECU985FaLbUWxuCQzBcitnhl+VSv19oEPHTJWu0nYabasfT4oPjf8eiWR/ymJ9DZrjMWWy4Xf/S+/nFYUCQQDIZ1pc9nZsCB4QiBl5agTXoMcKavxFHPKxI/mHfRCHYjNyirziBJ+Dc/N40zKvldNBjO43KjLhUZs/BxdAJo09AkEA7OAdsg6SmviVV8xk0vuTmgLxhD7aZ9vpV4KF5+TH2DbximFoOP3YRObXV862wAjCpa84v43ok7Imtsu3NKQ+iwJAc0mx3GUU/1U0JoKFVSm+m2Ws27tsYT4kB/AQLvetuJSv0CcsPkI2meLsoAev0v84Ry+SIz4tgx31V672mzsSaQJBAJET1rw2Vq5Zr8Y9ZkceVFGQmfGAOW5A71Jsm6zin0+anyc874NwXaQdqiiab61/8A9gGSahOKA1DacJcCTqr28CQGm4mn3rOQFf+nniajIobATjNHaZJ76Xnc6rtoreK6+ZjO9wYF+797X/bhiV11Fpakvyrz6+t7bAd0PPQ2taTDg="
        payload_bytes = bytes([0x34, 0x52, 0xe3, 0xd1, 0x1c, 0xdd, 0x70, 0xeb, 0x90, 0x32, 0x3f, 0x29, 0x1c, 0x06, 0xaf, 0xaf, 0xe1, 0x0e, 0x09, 0x8a])
        
        block = CustomRSA.encrypt_for_adobe_signature(base64.b64decode(mock_signing_key), payload_bytes)
        signature = base64.b64encode(block).decode()

        expected_signature = "RO/JmWrustzT50GB9bSb4VdRZCP77y0ZuFFmn8gk/p0E6EbQnqP10QkB5HM8JSV9lKaKJuZpDBJ8cp+FxZmMSPe6odTUiL134Y6tXOCllBtKwVamQjsYbIFLv/HOX68rUadSHpr4QKMle2jeQinIT0viS5kwO7XofKHaSLM2XjE="

        self.assertEqual(signature, expected_signature, "CustomRSA node hash signing method is broken")

    def test_pkcs12_extract(self): 
        '''Check if oscrypto can extract pkcs12'''

        from oscrypto import keys
        from oscrypto.asymmetric import dump_certificate, dump_private_key


        mock_p12_data = "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"
        mock_p12_password = b"1234"

        # I don't like having to import two external libraries just to extract pkcs12 data,
        # but I didn't find a proper Python-only solution for this, 
        # and I didn't want to implement OpenSSL interfaces on my own.

        privkey, cert, _ = keys.parse_pkcs12(base64.b64decode(mock_p12_data), mock_p12_password)
        cert = dump_certificate(cert, encoding="der")
        privkey = dump_private_key(privkey, None, "der")

        # privkey now is in PKCS#8 format. That's a wrapper around the actual PKCS#1 key. 
        # See https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for details.
        # Throw away the PKCS#8 wrapper: 
        privkey = privkey[26:]

        # Verify result:
        dummy_cert_data = base64.b64decode("MIICLjCCAZegAwIBAgIUI48XmtNFINg1znympL1l1SmSYnMwDQYJKoZIhvcNAQELBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxOTE0MzUyMVoXDTIxMTIyOTE0MzUyMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABo1MwUTAdBgNVHQ4EFgQUiG9zxWck82kn+BoVp3So+p6tFc8wHwYDVR0jBBgwFoAUiG9zxWck82kn+BoVp3So+p6tFc8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCpLSNaGDRNMGAzbTtUbyWzbvgT2+hcOaqr8+fyCWtUxZ1FiPIKZEcQRQOuqZZpWft5QJSYBZ2oc3O6NFU5VrBi5UI3rTqr2S97PiJCiR4Jt1vAcpXVy6qcEjTswdpipdsN4RSeiztYk4xoqYztPoiqKJgq9nOzuXFnDKrrrMo+5w==")
        dummy_key_data = base64.b64decode("MIICXQIBAAKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABAoGAI2CIGmHyDaTG7I2X9AS752AviVJhs586ay0ZBjYtKlsWoKa/GGJmFNTckHFMjGWgs/IZNyLnOnBlbhpX5UbO1cB7r9Vk1Q3fbIeQdBySyqOG9JfZxd0n4bBSHnopL0naGA0CpSv/tVaUr0BzvNYslw5rcwVinEbGVPP6JNNqbqECQQD1Igbf2qxMHcdEA81qMdExFGmlq61W7gpKtl7XwPhtHIiXyhQsT7M996ZF64EJVg/2/6gQneZ/awJ0Aw8xDkJdAkEAyymWou2v6wPtX+X0hnXnK6OfeEfZGnExE4LpEjNTiQriabvwmCQcgHFBLxKN+C4uVK5HBlHug3jtN0jozSjcVQJBAI+ynLkJJUuRgUhbukTwYyMURkI5+2kkLaBSfBKaKoc73M6uRVkcd4Rx8mS2g3QHoWA3yjvDdGVpQ4ziZjtpknkCQQC2FSsGEYM2Xgm0hlO24xrx+K7nTXWeBk7WzuB3SHsY+yFbZG7I3KySzW5/cuC8yx8JFD1hw7LCMHJitzy3C2UVAkAQGY8PQ9u40krQekUI+imFsPSPdMZqfMKJDLwrXx0mmElUYYZBGtY0q781UYP4GArtwyusDelk6BNjVRjiWUhg")

        self.assertEqual(cert, dummy_cert_data, "p12 cert invalid after extraction")
        self.assertEqual(privkey, dummy_key_data, "p12 key invalid after extraction")

    def test_pkcs12_extract_with_cryptography(self): 
        '''Check if cryptography (unused) can extract pkcs12'''

        # This uses cryptography.hazmat to extract the PKCS data. That's not what the plugin is using right now.

        mock_p12_data = "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"
        mock_p12_password = b"1234"

        try: 
            from cryptography.hazmat.primitives.serialization import pkcs12
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        except: 
            return self.skipTest("cryptography not installed")


        privkey, cert, _ = pkcs12.load_key_and_certificates(base64.b64decode(mock_p12_data), mock_p12_password)
        privkey = privkey.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        cert = cert.public_bytes(Encoding.DER)

        # privkey now is in PKCS#8 format. That's a wrapper around the actual PKCS#1 key. 
        # See https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for details.
        # Throw away the PKCS#8 wrapper: 
        privkey = privkey[26:]

        # Verify result:
        dummy_cert_data = base64.b64decode("MIICLjCCAZegAwIBAgIUI48XmtNFINg1znympL1l1SmSYnMwDQYJKoZIhvcNAQELBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxOTE0MzUyMVoXDTIxMTIyOTE0MzUyMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABo1MwUTAdBgNVHQ4EFgQUiG9zxWck82kn+BoVp3So+p6tFc8wHwYDVR0jBBgwFoAUiG9zxWck82kn+BoVp3So+p6tFc8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCpLSNaGDRNMGAzbTtUbyWzbvgT2+hcOaqr8+fyCWtUxZ1FiPIKZEcQRQOuqZZpWft5QJSYBZ2oc3O6NFU5VrBi5UI3rTqr2S97PiJCiR4Jt1vAcpXVy6qcEjTswdpipdsN4RSeiztYk4xoqYztPoiqKJgq9nOzuXFnDKrrrMo+5w==")
        dummy_key_data = base64.b64decode("MIICXQIBAAKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABAoGAI2CIGmHyDaTG7I2X9AS752AviVJhs586ay0ZBjYtKlsWoKa/GGJmFNTckHFMjGWgs/IZNyLnOnBlbhpX5UbO1cB7r9Vk1Q3fbIeQdBySyqOG9JfZxd0n4bBSHnopL0naGA0CpSv/tVaUr0BzvNYslw5rcwVinEbGVPP6JNNqbqECQQD1Igbf2qxMHcdEA81qMdExFGmlq61W7gpKtl7XwPhtHIiXyhQsT7M996ZF64EJVg/2/6gQneZ/awJ0Aw8xDkJdAkEAyymWou2v6wPtX+X0hnXnK6OfeEfZGnExE4LpEjNTiQriabvwmCQcgHFBLxKN+C4uVK5HBlHug3jtN0jozSjcVQJBAI+ynLkJJUuRgUhbukTwYyMURkI5+2kkLaBSfBKaKoc73M6uRVkcd4Rx8mS2g3QHoWA3yjvDdGVpQ4ziZjtpknkCQQC2FSsGEYM2Xgm0hlO24xrx+K7nTXWeBk7WzuB3SHsY+yFbZG7I3KySzW5/cuC8yx8JFD1hw7LCMHJitzy3C2UVAkAQGY8PQ9u40krQekUI+imFsPSPdMZqfMKJDLwrXx0mmElUYYZBGtY0q781UYP4GArtwyusDelk6BNjVRjiWUhg")

        self.assertEqual(cert, dummy_cert_data, "p12 cert invalid after extraction")
        self.assertEqual(privkey, dummy_key_data, "p12 key invalid after extraction")
   

    

    
    def test_Account_loginCredentialEncryption(self):
        '''Check if we can properly encrypt login credentials'''

        # This cert is not the actual Adobe auth cert. 
        # I added a fake one in here so we can also test if the encrypted data is valid
        # by just decrypting it again.
        # Also, I don't think I'd be allowed to redistribute the Adobe cert anyways.
        mock_auth_certificate = "MIICLjCCAZegAwIBAgIUPo11NtzZuIdqNySSJhG9ntZEpy0wDQYJKoZIhvcNAQEFBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxODIwNDYwMVoXDTIxMTIyODIwNDYwMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/NkUXHTEYAyQzm6BHekzyAM8EfjBvWCLAvOVBs/eTqKwrOfqkuT+TuIYfvBx/GuWx9szMi/sTL1R0vCLxhO6FxnZH+OW4OC8mi5oyfWQxiZe41Mo7o6FYnyMA+fuwz9TyeL2BmObH9HewVhTwmVesdTNOAwaH+neC/IJ5/yGDMwIDAQABo1MwUTAdBgNVHQ4EFgQUYlO/CiLaNR2Mlmg64KALHq3jq18wHwYDVR0jBBgwFoAUYlO/CiLaNR2Mlmg64KALHq3jq18wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQAzF75pKA2lzNxM+kPWErvJmOmP1aAWGZfbAG7naiC32pPHwNfKjUTQ1vpqoYxydvsmHzVhF1Z/czBdLMR8/PtSv+cGrhhLrc7c5uzp2YDZU4TiGaGz7jiD5C0rp3IpyEP3IN0SNeYwEZtKMph+pv3k5zcgsIPOsHIS0gwV3U70HA=="
        mock_auth_cert_private_key = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWEFJQkFBS0JnUUMvTmtVWEhURVlBeVF6bTZCSGVrenlBTThFZmpCdldDTEF2T1ZCcy9lVHFLd3JPZnFrCnVUK1R1SVlmdkJ4L0d1V3g5c3pNaS9zVEwxUjB2Q0x4aE82RnhuWkgrT1c0T0M4bWk1b3lmV1F4aVplNDFNbzcKbzZGWW55TUErZnV3ejlUeWVMMkJtT2JIOUhld1ZoVHdtVmVzZFROT0F3YUgrbmVDL0lKNS95R0RNd0lEQVFBQgpBb0dBSUxCaWQyVWlNM3kxLzZ5blpoRGVmckRzczFQdmE5bWhkMW5UeDd2QW81bStkVlZnS0RFVFVXbkdaRDZBCmtLcEVnbnd5M3ZVL1l6UkFPQVRCNUpCWlJuSEpzeHBmUk9sVHBZRHJBaXFoZ0dlZGNkSHozb1NhSk8zZVVZNzcKUEt6NDZ0VTNUTVZvMFdndmV0d3FKWXNEencxcHREa2Nqb2xxVGNYSWxhdTBGYUVDUVFEbERTTnNzWTM2VmlzSwpma0hNblJEd1FJdHFPNGlrZEtFRGNqTzU0Q3RXYVpjK2lGZ1FsMjFzUk1ueW91SVBzT3RBTG96V0wwMzJ2NTRHCk5XQUI1emkvQWtFQTFiVndJV1lzeVh6aHp5Wko4bWhmTGYvY2kydmQyY2RTK3lBTEwrbUpJQmJSejMvNFdHSFgKdUxXMWwxWGVLYWVmRnFob1JpTzdxUWpNWCthb3ZqYytqUUpCQU1TQ2F4djdrTlZ2UytucXZFVHhrL0NyVDNESwp0c1p4RVJyRnhiNzRwZld6RFlFbXRIYzNremRLSlFBMzRqNllDSnk5MHpLR3p4cWM5dFJZd28rZmNqMENRRWptCmY3Mms4Um82YzMwS2ZxY21XM0dCbW1ZbEFhVE1qYzRFZkV4M3ljTWNoYTNXNVl5Z3M4bmFrbnR4V3p1eVpsNkEKVERIQTlyOE90VWp4a2haeEdmRUNRRndVZlhEVncwNjlOaUdJRUpWRWVTRkp6TCszb1JSWCsrZ0krb3AwNlRBaApCcTFjemVZMWFOMllTWGIveDZ4TEI5amFYSXg1UElIM1Uyc3VhZHdETnNVPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="

        user = "username"
        passwd = "unit-test-password"

        libadobe.devkey_bytes = bytes([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])
        encrypted = libadobeAccount.encryptLoginCredentials(user, passwd, mock_auth_certificate)

        # Okay, now try to decrypt this again: 

        pkey = RSA.import_key(base64.b64decode(mock_auth_cert_private_key))
        cipher_engine = PKCS1_v1_5.new(pkey)
        msg = cipher_engine.decrypt(encrypted, bytes([0x00] * 16))

        expected_msg = bytearray(libadobe.devkey_bytes)
        expected_msg.extend(bytearray(len(user).to_bytes(1, 'big')))
        expected_msg.extend(bytearray(user.encode("latin-1")))
        expected_msg.extend(bytearray(len(passwd).to_bytes(1, 'big')))
        expected_msg.extend(bytearray(passwd.encode("latin-1")))

        self.assertEqual(msg.hex(), expected_msg.hex(), "devkey encryption returned invalid result")



class TestOther(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

    @unittest.skipIf(os.name == "nt", "not testing wine on Windows")
    def test_wineUsernameEscaping(self): 
        '''Check if Wine username decoder is working properly'''

        self.assertEqual(fix_wine_username(r'"1234"'),      b'1234',    "Wine username mismatch")
        self.assertEqual(fix_wine_username(r'"a\x00e931"'), b'a\xe931', "Wine username mismatch")

    def test_pdf_trimEncrypt(self): 
        '''Check if PDF encryption string trimming code is working properly'''

        input = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>AppendedData"
        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"

        self.assertEqual(trim_encrypt_string(input), output, "PDF string trimming broken")

    def test_pdf_cleanupEncrypt(self): 
        '''Check if PDF encryption string spacing code is working properly'''

        self.assertEqual(cleanup_encrypt_element("ID[<1111><2222>]"),       "ID[<1111> <2222>]", "angle bracket spacing invalid")
        self.assertEqual(cleanup_encrypt_element("ID[  <1111> <2222>]  "),  "ID[<1111> <2222>]", "square bracket spacing invalid")

    def test_pdf_deflateCompression(self): 
        '''Check if PDF rights.xml deflare code is working properly'''

        self.assertEqual(deflate_and_base64_encode(b""),                  b"AwA=",                  "deflate code error in empty string")
        self.assertEqual(deflate_and_base64_encode(b"Hello world"),       b"80jNyclXKM8vykkBAA==",  "deflate code error")
        self.assertEqual(deflate_and_base64_encode(b"Example AAAAAAAAA"), b"c61IzC3ISVVwhAEA",      "deflate code error")



# Patch to only display the docstring info, not the weird autogenerated name. 
def monkeypatch_getDescription(self, test):
    if test.shortDescription() is not None: 
        return test.shortDescription()
    
    return str(test)

# Patch the error list at the end to include the autogenerated name (use original getDescription, not my override)
def monkeypatch_printErrorList(self, flavour, errors):
    for test, err in errors:
        self.stream.writeln(self.separator1)
        self.stream.writeln("%s: %s" % (flavour,self.getFullDescription(test)))
        self.stream.writeln(self.separator2)
        self.stream.writeln("%s" % err)
        self.stream.flush()


if __name__ == "__main__":
    # Monkey patch the runner to get the output format I want:
    unittest.runner.TextTestResult.getFullDescription = unittest.runner.TextTestResult.getDescription
    unittest.runner.TextTestResult.getDescription = monkeypatch_getDescription
    unittest.runner.TextTestResult.printErrorList = monkeypatch_printErrorList

    # Run tests
    unittest.main(verbosity=2)

    
