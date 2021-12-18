#!/usr/bin/python3 -W ignore::DeprecationWarning

import sys
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


class TestAdobe(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")


    def test_checkIfVersionListsAreValid(self):
        '''These lists must have the same amount of elements, otherwise stuff will break.'''

        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_SUPP_VERSIONS),   "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_HOBBES_VERSIONS), "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_OS_IDENTIFIERS),  "Version lists seem to be invalid")
        self.assertEqual(len(libadobe.VAR_VER_SUPP_CONFIG_NAMES), len(libadobe.VAR_VER_BUILD_IDS),       "Version lists seem to be invalid")

    def test_checkSystemIdentifiers(self):
        '''Check if we can figure out necessary system IDs.'''
        self.assertEqual((len(libadobe.get_mac_address())), 6,  "MAC address invalid")
        self.assertEqual((len(libadobe.makeSerial(False))), 40, "SHA1 hash for device serial invalid (device-based)")
        self.assertEqual((len(libadobe.makeSerial(True))), 40,  "SHA1 hash for device serial invalid (random)")


    @patch("libadobe.Random")
    def test_deviceKeyEncryption(self, random):
        '''Check if encryption with the device key works properly.'''

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
        '''Check if decryption with the device key works properly.'''

        libadobe.devkey_bytes = bytes([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        mock_data = bytes([0xc2, 0x3b, 0x0f, 0xde, 0xf2, 0x4a, 0xc3, 0x03, 0xae, 0xc8, 0x70, 0xd4,
                           0x46, 0x6c, 0x8b, 0xb0, 0x23, 0x5a, 0xd3, 0x1b, 0x4e, 0x2b, 0x12, 0x79,
                           0x85, 0x63, 0x2d, 0x01, 0xa4, 0xe8, 0x29, 0x22])

        mock_result = libadobe.decrypt_with_device_key(mock_data)
        expected_result = b"Test message"

        self.assertEqual(mock_result, expected_result, "devkey decryption returned invalid result")

    @freeze_time("2021-12-18 22:07:15.988961")
    def test_verifyNonceCalculation(self): 
        '''Check if the nonce calculation is correct, at a given date/time.'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>8B2aPgg6AAAAAAAA</adept:nonce><adept:expiration>2021-12-18T22:17:15Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2021")

    
    @freeze_time("2031-07-19 22:15:22.074860")
    def test_verifyNonceCalculationFuture(self): 
        '''Check if the nonce calculation is still correct in the future.'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>JFUTp046AAAAAAAA</adept:nonce><adept:expiration>2031-07-19T22:25:22Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2031")


    
    def test_hash_node(self): 
        '''Check if the XML hash (needed for the signature) is correct.'''

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

        self.assertEqual(sha_hash, "3452e3d11cdd70eb90323f291c06afafe10e098a", "Invalid SHA hash after node signing")

    
    def test_Account_loginCredentialEncryption(self):
        '''Check if we can properly encrypt login credentials.'''

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

    def test_wineUsernameEscaping(self): 
        '''Wine uses a weird encoding for the username inside the registry. Make sure that the decoder is working correctly.'''

        self.assertEqual(fix_wine_username(r'"1234"'),      b'1234',    "Wine username mismatch")
        self.assertEqual(fix_wine_username(r'"a\x00e931"'), b'a\xe931', "Wine username mismatch")

    def test_pdf_trimEncrypt(self): 
        '''Makes sure the encryption string trimming code for PDFs is working fine.'''

        input = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>AppendedData"
        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"

        self.assertEqual(trim_encrypt_string(input), output, "PDF string trimming broken")

    def test_pdf_cleanupEncrypt(self): 
        '''Makes sure the encryption string cleanup / spacing code for PDFs is working fine.'''

        self.assertEqual(cleanup_encrypt_element("ID[<1111><2222>]"),       "ID[<1111> <2222>]")
        self.assertEqual(cleanup_encrypt_element("ID[  <1111> <2222>]  "),  "ID[<1111> <2222>]")

    def test_pdf_deflateCompression(self): 
        '''Makes sure the deflate code for PDF rights.xml works properly.'''

        self.assertEqual(deflate_and_base64_encode(b""),                  b"AwA=",                  "deflate code error in empty string")
        self.assertEqual(deflate_and_base64_encode(b"Hello world"),       b"80jNyclXKM8vykkBAA==",  "deflate code error")
        self.assertEqual(deflate_and_base64_encode(b"Example AAAAAAAAA"), b"c61IzC3ISVVwhAEA",      "deflate code error")






if __name__ == "__main__":
    unittest.main(verbosity=1)
    
