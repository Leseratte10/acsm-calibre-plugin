#!/usr/bin/python3 

import sys, os
sys.path.append("../calibre-plugin")


import unittest
import base64
from freezegun import freeze_time
if sys.version_info[0] >= 3:
    from unittest.mock import patch
else: 
    from mock import patch
from lxml import etree
import binascii


try: 
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_v1_5
except ImportError:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

import libadobe             # type: ignore
import libadobeAccount      # type: ignore
import libadobeFulfill      # type: ignore
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
        '''Check if version lists are sane'''

        '''
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
        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        self.assertEqual(libadobe.makeFingerprint("f0081bce3f771bdeeb26fcb4b2011fed77edff7b"), b"FgLMNXxv1BZPqMOM6IUnfaG4Qj8=", "Wrong fingerprint")
        self.assertEqual(libadobe.makeFingerprint("HelloWorld123"),                            b"hpp223C1kfLDOoyxo8WR7KhcXB8=", "Wrong fingerprint")


    @patch("libadobe.Random")
    def test_deviceKeyEncryption(self, random):
        '''Check if encryption with the device key works'''

        # Overwrite the get_random_bytes function that's used to get a random IV
        # Forcing hard-coded IV ...
        random.get_random_bytes._mock_side_effect = lambda rndlen: bytearray([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 
                                                                          0xae, 0xc8, 0x70, 0xd4, 0x46, 0x6c, 0x8b, 0xb0])


        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])
        mock_data = b"Test message"
        mock_result = libadobe.encrypt_with_device_key(mock_data)
        expected_result = bytearray([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 0xae, 0xc8, 0x70, 0xd4,
                                 0x46, 0x6c, 0x8b, 0xb0, 0x23, 0x5a, 0xd3, 0x1b, 0x4e, 0x2b, 0x12, 0x79,
                                 0x85, 0x63, 0x2d, 0x01, 0xa4, 0xe8, 0x29, 0x22])
        
        self.assertEqual(mock_result, expected_result, "devkey encryption returned invalid result")

    def test_deviceKeyDecryption(self):
        '''Check if decryption with the device key works'''

        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        mock_data = bytearray([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 0xae, 0xc8, 0x70, 0xd4,
                           0x46, 0x6c, 0x8b, 0xb0, 0x23, 0x5a, 0xd3, 0x1b, 0x4e, 0x2b, 0x12, 0x79,
                           0x85, 0x63, 0x2d, 0x01, 0xa4, 0xe8, 0x29, 0x22])

        mock_result = libadobe.decrypt_with_device_key(mock_data)
        expected_result = b"Test message"

        self.assertEqual(mock_result, expected_result, "devkey decryption returned invalid result")

    @freeze_time("2021-12-18 22:07:15.988961")
    def test_verifyNonceCalculation(self): 
        '''Check if the nonce calculation is correct, at a given date/time'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>FBqaPgg6AAAAAAAA</adept:nonce><adept:expiration>2021-12-18T22:17:15Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2021")


    
    @freeze_time("2031-07-19 22:15:22.074860")
    def test_verifyNonceCalculationFuture(self): 
        '''Check if the nonce calculation is still correct in the future'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>2lQTp046AAAAAAAA</adept:nonce><adept:expiration>2031-07-19T22:25:22Z</adept:expiration>"
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


    def test_hash_node_returnbugfix(self): 
        '''Check if the XML hash is correct when returning a book ...'''

        # I don't think there's ever a case where the hashing algorithm is different, 
        # but I needed this test during debugging and thought, hey, why not leave it in. 

        mock_xml_str = """
        <adept:notification xmlns:adept="http://ns.adobe.com/adept">
        <adept:user>urn:uuid:6e5393e0-ff13-4ae8-8f6c-6654182ac7d5</adept:user>
        <adept:device>urn:uuid:51abfbaf-f0e8-474d-b031-626c5224f90f</adept:device>
        <adept:nonce>eVr2pi26AAAAAAAA</adept:nonce>
        <adept:expiration>2022-08-03T09:16:22Z</adept:expiration>
            <body xmlns="http://ns.adobe.com/adept">
                <fulfillment>6ccfbc7a-349b-40ad-82d8-d7a4c717ca13-00000271</fulfillment>
                <transaction>237493726-1749302749327354-Wed Aug 03 09:16:22 UTC 2022</transaction>
                <user>urn:uuid:6e5393e0-ff13-4ae8-8f6c-6654182ac7d5</user>
                <fulfilled>true</fulfilled>
                <returned>true</returned>
                <hmac>CB3Ql1FAJD957t5n749q5ZO8IzU=</hmac>
            </body>
        </adept:notification>
        """

        mock_xml_obj = etree.fromstring(mock_xml_str)
        sha_hash = libadobe.hash_node(mock_xml_obj).hexdigest().lower()

        self.assertEqual(sha_hash, "8b0a24ba37c4333d93650c6ce52f8ee779f21533", "Invalid SHA hash for node signing")




    def test_sign_node_old(self):

        '''Check if the external RSA library (unused) signs correctly'''

        # This is no longer in use by the plugin, but I still want to leave this test in,
        # in case we need to go back to the old method.

        mock_signing_key = "MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBALluuPvdDpr4L0j3eIGy3VxhgRcEKU3++qwbdvLXI99/izW9kfELFFJtq5d4ktIIUIvHsWkW0jblGi+bQ4sQXCeIvtOgqVHMSvRpW78lnGEkdD4Y1qhbcVGw7OGpWlhp8qCJKVCGbrkML7BSwFvQqqvg4vMU8O1uALfJvicKN3YfAgMBAAECf3uEg+Hr+DrstHhZF40zJPHKG3FkFd3HerXbOawMH5Q6CKTuKDGmOYQD+StFIlMArQJh8fxTVM3gSqgPkyyiesw0OuECU985FaLbUWxuCQzBcitnhl+VSv19oEPHTJWu0nYabasfT4oPjf8eiWR/ymJ9DZrjMWWy4Xf/S+/nFYUCQQDIZ1pc9nZsCB4QiBl5agTXoMcKavxFHPKxI/mHfRCHYjNyirziBJ+Dc/N40zKvldNBjO43KjLhUZs/BxdAJo09AkEA7OAdsg6SmviVV8xk0vuTmgLxhD7aZ9vpV4KF5+TH2DbximFoOP3YRObXV862wAjCpa84v43ok7Imtsu3NKQ+iwJAc0mx3GUU/1U0JoKFVSm+m2Ws27tsYT4kB/AQLvetuJSv0CcsPkI2meLsoAev0v84Ry+SIz4tgx31V672mzsSaQJBAJET1rw2Vq5Zr8Y9ZkceVFGQmfGAOW5A71Jsm6zin0+anyc874NwXaQdqiiab61/8A9gGSahOKA1DacJcCTqr28CQGm4mn3rOQFf+nniajIobATjNHaZJ76Xnc6rtoreK6+ZjO9wYF+797X/bhiV11Fpakvyrz6+t7bAd0PPQ2taTDg="
        payload_bytes = bytearray([0x34, 0x52, 0xe3, 0xd1, 0x1c, 0xdd, 0x70, 0xeb, 0x90, 0x32, 0x3f, 0x29, 0x1c, 0x06, 0xaf, 0xaf, 0xe1, 0x0e, 0x09, 0x8a])
        
        try: 
            import rsa
        except: 
            return self.skipTest("rsa not installed")

        key = rsa.PrivateKey.load_pkcs1(RSA.importKey(base64.b64decode(mock_signing_key)).exportKey())
        keylen = rsa.pkcs1.common.byte_size(key.n)
        padded = rsa.pkcs1._pad_for_signing(bytes(payload_bytes), keylen)
        payload = rsa.pkcs1.transform.bytes2int(padded)
        encrypted = key.blinded_encrypt(payload)
        block = rsa.pkcs1.transform.int2bytes(encrypted, keylen)
        signature = base64.b64encode(block).decode()

        expected_signature = "RO/JmWrustzT50GB9bSb4VdRZCP77y0ZuFFmn8gk/p0E6EbQnqP10QkB5HM8JSV9lKaKJuZpDBJ8cp+FxZmMSPe6odTUiL134Y6tXOCllBtKwVamQjsYbIFLv/HOX68rUadSHpr4QKMle2jeQinIT0viS5kwO7XofKHaSLM2XjE="

        self.assertEqual(signature, expected_signature, "Old (external RSA) node hash signing method broken")


    def test_sign_node_new(self):

        '''Check if the builtin CustomRSA library signs correctly'''

        mock_signing_key = "MIICdAIBADANBgkqhkiG9w0BAQEFAASCAl4wggJaAgEAAoGBALluuPvdDpr4L0j3eIGy3VxhgRcEKU3++qwbdvLXI99/izW9kfELFFJtq5d4ktIIUIvHsWkW0jblGi+bQ4sQXCeIvtOgqVHMSvRpW78lnGEkdD4Y1qhbcVGw7OGpWlhp8qCJKVCGbrkML7BSwFvQqqvg4vMU8O1uALfJvicKN3YfAgMBAAECf3uEg+Hr+DrstHhZF40zJPHKG3FkFd3HerXbOawMH5Q6CKTuKDGmOYQD+StFIlMArQJh8fxTVM3gSqgPkyyiesw0OuECU985FaLbUWxuCQzBcitnhl+VSv19oEPHTJWu0nYabasfT4oPjf8eiWR/ymJ9DZrjMWWy4Xf/S+/nFYUCQQDIZ1pc9nZsCB4QiBl5agTXoMcKavxFHPKxI/mHfRCHYjNyirziBJ+Dc/N40zKvldNBjO43KjLhUZs/BxdAJo09AkEA7OAdsg6SmviVV8xk0vuTmgLxhD7aZ9vpV4KF5+TH2DbximFoOP3YRObXV862wAjCpa84v43ok7Imtsu3NKQ+iwJAc0mx3GUU/1U0JoKFVSm+m2Ws27tsYT4kB/AQLvetuJSv0CcsPkI2meLsoAev0v84Ry+SIz4tgx31V672mzsSaQJBAJET1rw2Vq5Zr8Y9ZkceVFGQmfGAOW5A71Jsm6zin0+anyc874NwXaQdqiiab61/8A9gGSahOKA1DacJcCTqr28CQGm4mn3rOQFf+nniajIobATjNHaZJ76Xnc6rtoreK6+ZjO9wYF+797X/bhiV11Fpakvyrz6+t7bAd0PPQ2taTDg="
        payload_bytes = bytearray([0x34, 0x52, 0xe3, 0xd1, 0x1c, 0xdd, 0x70, 0xeb, 0x90, 0x32, 0x3f, 0x29, 0x1c, 0x06, 0xaf, 0xaf, 0xe1, 0x0e, 0x09, 0x8a])
        
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
   

    def test_pkcs12_extract_plugin_implementation(self): 
        '''Check if the plugin is capable of extracting pkcs12 key'''

        mock_p12_data = "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"
        # Actual key password is "1234" base64-encoded = "MTIzNA=="

        mock_p12_password = b"1234"

        libadobe.devkey_bytes = mock_p12_password

        decrypted = libadobeFulfill.getDecryptedCert(mock_p12_data)

        self.assertIsNotNone(decrypted)

    
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

        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])
        encrypted = libadobeAccount.encryptLoginCredentials(user, passwd, mock_auth_certificate)

        # Okay, now try to decrypt this again: 

        pkey = RSA.import_key(base64.b64decode(mock_auth_cert_private_key))
        cipher_engine = PKCS1_v1_5.new(pkey)
        msg = cipher_engine.decrypt(encrypted, bytes([0x00] * 16))

        import struct

        expected_msg = bytearray(libadobe.devkey_bytes)
        expected_msg.extend(bytearray(struct.pack("B", len(user))))
        expected_msg.extend(bytearray(user.encode("latin-1")))
        expected_msg.extend(bytearray(struct.pack("B", len(passwd))))
        expected_msg.extend(bytearray(passwd.encode("latin-1")))

        self.assertEqual(binascii.hexlify(msg), binascii.hexlify(expected_msg), "devkey encryption returned invalid result")


class TestPluginInterface(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

    def test_loanReturnFulfillmentID(self): 
        '''Check if proper ID is used for the loan token'''

        # Previous versions of the plugin had a bug where sometimes the wrong loan token
        # was used, which caused wrong (or no) books to be returned to a library. 
        # Adding a test case so this never happens again ...


        mock_data = """

        <envelope xmlns="http://ns.adobe.com/adept">
            <fulfillmentResult>
                <fulfillment>34659b20-92c8-4004-9fd8-c5174e7eed47-00010214</fulfillment>
                <returnable>true</returnable>
                <initial>false</initial>
                <resourceItemInfo>
                    <resource>urn:uuid:b7c6ccb8-1012-44a9-9c8b-0388d0c685f7</resource>
                    <resourceItem>0</resourceItem>
                    <metadata>
                        <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Book title for test</dc:title>
                    </metadata>
                    <licenseToken>
                        <user>urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa</user>
                        <resource>urn:uuid:b7c6ccb8-1012-44a9-9c8b-0388d0c685f7</resource>
                        <deviceType>standalone</deviceType>
                        <device>urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84</device>
                        <operatorURL>https://acs.example.com/fulfillment</operatorURL>
                        <fulfillment>34659b20-92c8-4004-9fd8-c5174e7eed47-00010214</fulfillment>
                        <distributor>urn:uuid:1f5c2437-58f2-4a24-9495-3e99155e6f98</distributor>
                        <permissions>
                            <display>
                                <loan>34659b20-92c8-4004-9fd8-c5174e7eed47-00010214</loan>
                                <until>2022-07-03T01:14:42Z</until>
                            </display>
                        </permissions>
                    </licenseToken>
                </resourceItemInfo>
            </fulfillmentResult>

            <loanToken>
                <time>2022-07-01T03:17:22+00:00</time>
                <user>urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa</user>
                <operatorURL>https://acs.example.com/fulfillment</operatorURL>
                <licenseURL>https://nasigningservice.adobe.com/licensesign</licenseURL>
                <loan>6d2dc249-2bc0-43e1-a130-3866f85020d9-00003487</loan>
                <loan>6d2dc249-2bc0-43e1-a130-3866f85020d9-00003467</loan>
                <loan>34659b20-92c8-4004-9fd8-c5174e7eed47-00010214</loan>
                <loan>11197eb9-3543-4b41-9c6e-03ffeaf277c0-00024754</loan>
            </loanToken>
        </envelope>

        """


        extracted_token = libadobeFulfill.updateLoanReturnData(etree.fromstring(mock_data), forceTestBehaviour=True)

        expected_token = {
            "book_name": "Book title for test",
            "device": 'urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84',
            "user": 'urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa',
            "operatorURL": 'https://acs.example.com/fulfillment',
            "loanID": '34659b20-92c8-4004-9fd8-c5174e7eed47-00010214',
            "validUntil": '2022-07-03T01:14:42Z'
        }

        self.assertEqual(extracted_token, expected_token, "Loan record generator broken")



class TestOther(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

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

    
