#!/usr/bin/python3 
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

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
    from Crypto.PublicKey import RSA            # type: ignore
    from Crypto.Cipher import PKCS1_v1_5        # type: ignore

from acsm_input import libadobe             # type: ignore
from acsm_input import libadobeAccount      # type: ignore
from acsm_input import libadobeFulfill      # type: ignore
from acsm_input.customRSA import CustomRSA # type: ignore


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


    def test_sslContextValidation(self):
        '''Check if validate_tls actually turns certificate validation on and off'''

        import ssl

        ctx = libadobe.create_ssl_context(True)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED, "validate_tls=True doesn't require a certificate")
        self.assertTrue(ctx.check_hostname, "validate_tls=True doesn't check the hostname")

        ctx = libadobe.create_ssl_context(False)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE, "validate_tls=False still requires a certificate")
        self.assertFalse(ctx.check_hostname, "validate_tls=False still checks the hostname")


    def test_safeXMLParser(self):
        '''Check if XML from servers and ACSM files can't pull in local files (XXE)'''

        # Before lxml 5.0, the default parser resolves external entities, so a DOCTYPE in
        # a server reply or an ACSM file could put the contents of a local file into the
        # parsed XML, and from there into a request.

        import tempfile, shutil
        try:
            from urllib.request import pathname2url
        except ImportError:
            from urllib import pathname2url

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        tmp_dir = tempfile.mkdtemp()
        try:
            secret_path = os.path.join(tmp_dir, "secret.txt")
            with open(secret_path, "w") as f:
                f.write("SECRET")

            mock_xml_str = """<!DOCTYPE licenseServiceInfo [
              <!ENTITY ext SYSTEM "file:%s">
              <!ENTITY int "INTERNAL">
            ]>
            <licenseServiceInfo xmlns="http://ns.adobe.com/adept">
              <licenseURL>https://example.com/&ext;</licenseURL>
              <certificate>&int;</certificate>
              <operatorURL>https://example.com/?a=1&amp;b=2&#38;c=3</operatorURL>
            </licenseServiceInfo>""" % (pathname2url(secret_path))

            mock_xml_path = os.path.join(tmp_dir, "book.acsm")
            with open(mock_xml_path, "w") as f:
                f.write(mock_xml_str)

            # A parser that resolves entities really loads the file, so the test can fail
            unsafe = etree.fromstring(mock_xml_str, parser=etree.XMLParser(resolve_entities=True))
            self.assertEqual(unsafe.find(adNS("licenseURL")).text, "https://example.com/SECRET", "Test setup is broken")

            parsed = [
                etree.fromstring(mock_xml_str, parser=libadobe.safe_xml_parser()),
                etree.parse(mock_xml_path, parser=libadobe.safe_xml_parser()).getroot()
            ]
            for xml in parsed:
                self.assertEqual(xml.find(adNS("licenseURL")).text, "https://example.com/", "External entity was resolved")
                self.assertNotEqual(xml.find(adNS("certificate")).text, "INTERNAL", "Internal entity was expanded")
                # Predefined entities and character references still work
                self.assertEqual(xml.find(adNS("operatorURL")).text, "https://example.com/?a=1&b=2&c=3", "Escaped characters are broken")
        finally:
            shutil.rmtree(tmp_dir)


    def test_serialGeneration(self):
        '''Check if serial generation works'''
        self.assertEqual((len(libadobe.get_mac_address())), 6,  "MAC address invalid")
        self.assertEqual(libadobe.get_mac_address(), libadobe.get_mac_address(), "MAC address not constant")
        self.assertEqual((len(libadobe.makeSerial(False))), 40, "SHA1 hash for device serial invalid (device-based)")
        self.assertEqual((len(libadobe.makeSerial(True))), 40,  "SHA1 hash for device serial invalid (random)")
        self.assertEqual(libadobe.makeSerial(False), libadobe.makeSerial(False), "Two non-random serials not identical")
        self.assertNotEqual(libadobe.makeSerial(True), libadobe.makeSerial(True), "Two random serials are identical ...")

        self.assertIsInstance(libadobe.makeSerial(True), str, "Serial must be a string, not bytes!")
        self.assertIsInstance(libadobe.makeSerial(False), str, "Serial must be a string, not bytes!")

    def test_serialGenerationNonASCIIUser(self):
        '''Check if serial generation works with a user name that isn't ASCII'''

        # Python 2 returns the user name as a byte string in the system's encoding, which
        # made makeSerial crash. It has to give the same serial as the name as text.

        import getpass, hashlib

        name = b"j\xc3\xbcrgen".decode("utf-8")
        name_bytes = name.encode("mbcs" if sys.platform == "win32" else "utf-8")

        class PasswdEntry:
            def __init__(self, pw_name):
                self.pw_name = pw_name

        def serial_for(user):
            with patch.object(os, "getlogin", return_value=user, create=True), \
                    patch.object(getpass, "getuser", return_value=user):
                try:
                    import pwd
                except ImportError:
                    # Windows
                    return libadobe.makeSerial(False)
                with patch.object(pwd, "getpwuid", return_value=PasswdEntry(user)):
                    return libadobe.makeSerial(False)

        serial = serial_for(name)
        self.assertEqual(serial_for(name_bytes), serial, "A user name as a byte string gives a different serial")

        # The serial is still the SHA-1 of "uid:user name as UTF-8:MAC address" and a null byte
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        mac = tuple(bytearray(libadobe.get_mac_address()))
        data_to_hash = ("%d:" % uid).encode("ascii") + name.encode("utf-8") + (":%02x:%02x:%02x:%02x:%02x:%02x\x00" % mac).encode("ascii")
        self.assertEqual(serial, hashlib.sha1(data_to_hash).hexdigest().lower(), "The serial for a user name as text changed")


    def test_deviceNameNonASCII(self):
        '''Check if device.xml is correct for a computer name that isn't ASCII'''

        # Python 2 returns the computer name as a byte string in the system's encoding,
        # which lxml rejects. The import code also inserted it without escaping it.

        import tempfile, shutil, platform
        from acsm_input import libadobeImportAccount       # type: ignore

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        name = b"B\xc3\x9cRO & <Co>".decode("utf-8")
        uname = list(platform.uname())
        uname[1] = name.encode("mbcs" if sys.platform == "win32" else "utf-8")

        mock_mac_activation_xml = b"""<?xml version="1.0"?>
<activationInfo xmlns="http://ns.adobe.com/adept">
  <adept:activationToken xmlns:adept="http://ns.adobe.com/adept">
    <adept:deviceType>standalone</adept:deviceType>
  </adept:activationToken>
</activationInfo>
"""

        mock_import_data = {
            "activationServiceInfo": {
                "authURL": "https://example.com/auth", "userInfoURL": "https://example.com/userinfo",
                "activationURL": "https://example.com/activate", "certificate": "Q0VSVA==",
                "authenticationCertificate": "QVVUSA=="
            },
            "credentials": {
                "user": "urn:uuid:11111111-2222-3333-4444-555555555555", "pkcs12": "UEtDUzEy",
                "licenseCertificate": "TElD", "privateLicenseKey": "S0VZ", "authenticationCertificate": "QVVUSA=="
            },
            "activationToken": {
                "device": "urn:uuid:66666666-7777-8888-9999-000000000000", "fingerprint": "RklOR0VS",
                "deviceType": "standalone", "activationURL": "https://example.com/activate",
                "user": "urn:uuid:11111111-2222-3333-4444-555555555555", "signature": "U0lH"
            }
        }

        tmp_dir = tempfile.mkdtemp()
        try:
            dev_xml_path = os.path.join(tmp_dir, "device.xml")

            with patch.object(platform, "uname", return_value=tuple(uname)), \
                    patch.object(libadobe, "FILE_DEVICEXML", dev_xml_path), \
                    patch.object(libadobe, "FILE_ACTIVATIONXML", os.path.join(tmp_dir, "activation.xml")), \
                    patch.object(libadobe, "FILE_DEVICEKEY", os.path.join(tmp_dir, "devicesalt")), \
                    patch.object(libadobe, "devkey_bytes", bytearray(16)):

                self.assertEqual(libadobe.get_device_name(), name, "Wrong computer name")

                # New authorization
                self.assertTrue(libadobeAccount.createDeviceFile(True, 0), "createDeviceFile failed")
                self.assertEqual(etree.parse(dev_xml_path).find(adNS("deviceName")).text, name, "Wrong deviceName for a new authorization")

                # Import from ADE on Windows or in Wine
                result, msg = libadobeImportAccount.finalize_write_config_Windows(mock_import_data, bytearray(16), libadobe.VAR_VER_DEFAULT_BUILD_ID)
                self.assertTrue(result, msg)
                self.assertEqual(etree.parse(dev_xml_path).find(adNS("deviceName")).text, name, "Wrong deviceName after a Windows import")

                # Import from ADE on macOS
                mac_activation_path = os.path.join(tmp_dir, "activation.dat")
                with open(mac_activation_path, "wb") as f:
                    f.write(mock_mac_activation_xml)
                result, msg = libadobeImportAccount.recreateMacActivationFiles(mac_activation_path, bytearray(16), b"fingerprint", libadobe.VAR_VER_DEFAULT_BUILD_ID)
                self.assertTrue(result, msg)
                self.assertEqual(etree.parse(dev_xml_path).find(adNS("deviceName")).text, name, "Wrong deviceName after a macOS import")
        finally:
            shutil.rmtree(tmp_dir)


    def test_fingerprintGeneration(self): 
        '''Check if fingerprint generation works'''
        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])

        self.assertEqual(libadobe.makeFingerprint("f0081bce3f771bdeeb26fcb4b2011fed77edff7b"), b"FgLMNXxv1BZPqMOM6IUnfaG4Qj8=", "Wrong fingerprint")
        self.assertEqual(libadobe.makeFingerprint("HelloWorld123"),                            b"hpp223C1kfLDOoyxo8WR7KhcXB8=", "Wrong fingerprint")


    @patch("acsm_input.libadobe.Random")
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


    

    @freeze_time("2038-04-27 03:34:32.543157")
    def test_verifyNonceCalculationYk38(self): 
        '''Check if the nonce calculation works after 2038'''

        nonce_return = libadobe.addNonce()
        expected_return = "<adept:nonce>X0fGZ4A6AAAAAAAA</adept:nonce><adept:expiration>2038-04-27T03:44:32Z</adept:expiration>"
        self.assertEqual(nonce_return, expected_return, "Invalid nonce calculation in 2038, 2k38 problem")



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

    def test_pkcs12_extract_with_oscrypto(self): 
        '''Check if oscrypto (unused) can extract pkcs12'''

        from oscrypto import keys
        from oscrypto.asymmetric import dump_certificate, dump_private_key


        mock_p12_data = "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"
        mock_p12_password = base64.b64encode(b"1234")

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

    def __internal_pkcs12_extract_with_customcrypto(self, cert_b64, password): 
        try: 
            from customcrypto.customcrypto import keys
            from customcrypto.customcrypto.asymmetric import dump_certificate, dump_private_key
        except ModuleNotFoundError:
            try: 
                from customcrypto import keys
                from customcrypto.asymmetric import dump_certificate, dump_private_key
            except ModuleNotFoundError:
                return self.skipTest("customcrypto not found")

        privkey, cert, _ = keys.parse_pkcs12(base64.b64decode(cert_b64), password)
        cert = dump_certificate(cert, encoding="der")
        privkey = dump_private_key(privkey, None, "der")

        # privkey now is in PKCS#8 format. That's a wrapper around the actual PKCS#1 key. 
        # See https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem for details.
        # Throw away the PKCS#8 wrapper: 
        privkey = privkey[26:]

        return (cert, privkey)
    
    def test_pkcs12_extract_with_customcrypto_rc2(self): 
        '''Check if customcrypto can extract RC2 pkcs12'''

        mock_p12_data = "MIIGKQIBAzCCBe8GCSqGSIb3DQEHAaCCBeAEggXcMIIF2DCCAtcGCSqGSIb3DQEHBqCCAsgwggLEAgEAMIICvQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIl5CVTvXyuIsCAggAgIICkLnq1kOADD2LS1TwPvmNfNxLOVzoCunvV9dl01LDA+FnoL4JhuNE162irRCSsuruJuYs1EiFSVJi1qsLvi/yxhCw0Cty3EDpBpIaHKqEGBw7CXGFtCFAPX24ZcQuME2g3zKeM4hW7/e/Yrywhx0K9++yi8UvWSih7eEY25Ofk54TB4aKTiZwo4lQF5+xCUTI6y+RyeRqUv/QI2Z3YlGeU85+5pZxrlnEC7H22BncL8zqDOXeuyMcDPslEoSg3kuVqvuVCDx81vozroVmLcIQKtQuBA4L5U7XpW7BA8qO2346DbnAgwfM+HGNdc4nRtGSxLos/WrbYTTS4Q6Ao3+UOt4YOxMGlD4y8hLQ+XeAj2iKzU/PjK0T9q4DG+FHIUXlSKL117ZHTLRpMpEnZIHqUzEfSipGqRHXsV9vO4fUdDOdYcMXY4UgnTiiPT5a1m8WnWDUfAqOYWSGGgG8Z0QL9HTmZ/IfsV4cV1eAnwFtPXU3qpFoNGhNHmbNtN8N/AxB0DDGLnSUpm9YWRDtFYhxm5msOHn9yKuNzdGD8lMh0QymxGmS0OW4bs2QbtS7Rd+STYHC0NWuTWJkuYoSo9N7DsAEEMHcakJtN0g1D5H8aUHXLeanBDdh6Q96/fzviLFLYzhU2diyjyOQGdmxcqPIU73qG9dHqufe35wzGyJcKRz7xAoyHkX8S9sMgcm7uPeHd9v1jJYjP41SG+WL6HUIMJ5GNyw3xEvhr/kDgqEDvMK4+85K4/jlfPq+mMxk4o2jSOpORPi+ozyveKg7vIf/f1q7HdPMP9GV21TehouKf7yn8D+ZJ2LuZ3tyB0BM3IOFj468/Pl9PCFU4n4hR6oOYBz1Jhfk4okIvZ+XP187ACX4MIIC+QYJKoZIhvcNAQcBoIIC6gSCAuYwggLiMIIC3gYLKoZIhvcNAQwKAQKgggKmMIICojAcBgoqhkiG9w0BDAEDMA4ECK6O0EMY+9BAAgIIAASCAoAqSooxnudMd8c6UokswCl9AFWJ4Pi31ts5pcYmnHxIxi95G23uPiYdM9I1LuD8aPb+gT5MlIHwdZnOyB8ijJDIgddmX9fK1/I1qEHscgQX1+91QcmS+yQwZvbDYjaNOYlOpkKM39XY0uDYDU4/pKKH/QRpzruVnzthrbMAoOxatQf6o9/WNvkPpUh9ObAfmOkJ6ROEfEw9WWyDDyFbB7neHFGPUn9w7oLTnqUFbL6SKMHxk6Xn6XsfkHNfwURX59BYGk8ADv2oFYC/kus+pClmTUCChnC95GHwKa1Tt6+IFha92Kn+7IjriMlhrLKj3dEFFmgieXOC11ucCAMNIuhj4Z+03clmhUGSr5SLEwB3TF6MNou52wUvRArTKOj80N03aM09cYr50Tn6rwNtZdOq3ye3Q0ufQOA9HfY+FpGZq/9DXMhEy69d8weg3UyP+qvgayHOp5kFkYYbGcEO3FGebnHWtJ4NiQof3nRG/GhQFHIucFu+8g3udW8AhzGaTZWWcwWKr1w79jnh4QWOiD1f9T/TIRGHZKglHxakEs+0w3ddPNlINWy19F/4WXgB+zyifExCRmqWlRl7Co/sC7PhyrrbAGW8qQrhMn011v+Kl+qYPqPeeyRvDuJKgbHiAaF6qaDEzusWbLc4RQeSzyddJCU8kupp7tXcOKpff7FRUeM20u7UDCujUOnOYaCSOwHJt7hlaUyZIFOeOo14gYnlNrlVQAFojsaCg8e5aNN5oNXNUkaQlNGndN6R2R/U2BoNYaXeQpsivnvqd9x2mcJXnp3GXQdzQU/jBmkMpFuUNL5xw1apSwOr1Acg/lexV1SaL9VF3miwzyUvEOSd15VvMSUwIwYJKoZIhvcNAQkVMRYEFBWdk0i2wUp0ttbIxaNF7x0aJrb5MDEwITAJBgUrDgMCGgUABBS/f/lEORIZ260ej1viE3zfsPuODgQILxydt7pTNuQCAggA"
        mock_p12_password = b"1234"

        cert, privkey = self.__internal_pkcs12_extract_with_customcrypto(mock_p12_data, mock_p12_password)

        dummy_cert_data = base64.b64decode("MIICLjCCAZegAwIBAgIUI48XmtNFINg1znympL1l1SmSYnMwDQYJKoZIhvcNAQELBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxOTE0MzUyMVoXDTIxMTIyOTE0MzUyMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABo1MwUTAdBgNVHQ4EFgQUiG9zxWck82kn+BoVp3So+p6tFc8wHwYDVR0jBBgwFoAUiG9zxWck82kn+BoVp3So+p6tFc8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCpLSNaGDRNMGAzbTtUbyWzbvgT2+hcOaqr8+fyCWtUxZ1FiPIKZEcQRQOuqZZpWft5QJSYBZ2oc3O6NFU5VrBi5UI3rTqr2S97PiJCiR4Jt1vAcpXVy6qcEjTswdpipdsN4RSeiztYk4xoqYztPoiqKJgq9nOzuXFnDKrrrMo+5w==")
        dummy_key_data = base64.b64decode("MIICXQIBAAKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABAoGAI2CIGmHyDaTG7I2X9AS752AviVJhs586ay0ZBjYtKlsWoKa/GGJmFNTckHFMjGWgs/IZNyLnOnBlbhpX5UbO1cB7r9Vk1Q3fbIeQdBySyqOG9JfZxd0n4bBSHnopL0naGA0CpSv/tVaUr0BzvNYslw5rcwVinEbGVPP6JNNqbqECQQD1Igbf2qxMHcdEA81qMdExFGmlq61W7gpKtl7XwPhtHIiXyhQsT7M996ZF64EJVg/2/6gQneZ/awJ0Aw8xDkJdAkEAyymWou2v6wPtX+X0hnXnK6OfeEfZGnExE4LpEjNTiQriabvwmCQcgHFBLxKN+C4uVK5HBlHug3jtN0jozSjcVQJBAI+ynLkJJUuRgUhbukTwYyMURkI5+2kkLaBSfBKaKoc73M6uRVkcd4Rx8mS2g3QHoWA3yjvDdGVpQ4ziZjtpknkCQQC2FSsGEYM2Xgm0hlO24xrx+K7nTXWeBk7WzuB3SHsY+yFbZG7I3KySzW5/cuC8yx8JFD1hw7LCMHJitzy3C2UVAkAQGY8PQ9u40krQekUI+imFsPSPdMZqfMKJDLwrXx0mmElUYYZBGtY0q781UYP4GArtwyusDelk6BNjVRjiWUhg")

        self.assertEqual(cert, dummy_cert_data, "p12 cert invalid after extraction")
        self.assertEqual(privkey, dummy_key_data, "p12 key invalid after extraction")

    def test_pkcs12_extract_with_customcrypto_aes(self): 
        '''Check if customcrypto can extract AES pkcs12'''

        mock_p12_data = "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"
        mock_p12_password = base64.b64encode(b"1234")

        cert, privkey = self.__internal_pkcs12_extract_with_customcrypto(mock_p12_data, mock_p12_password)

        dummy_cert_data = base64.b64decode("MIICLjCCAZegAwIBAgIUI48XmtNFINg1znympL1l1SmSYnMwDQYJKoZIhvcNAQELBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxOTE0MzUyMVoXDTIxMTIyOTE0MzUyMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABo1MwUTAdBgNVHQ4EFgQUiG9zxWck82kn+BoVp3So+p6tFc8wHwYDVR0jBBgwFoAUiG9zxWck82kn+BoVp3So+p6tFc8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCpLSNaGDRNMGAzbTtUbyWzbvgT2+hcOaqr8+fyCWtUxZ1FiPIKZEcQRQOuqZZpWft5QJSYBZ2oc3O6NFU5VrBi5UI3rTqr2S97PiJCiR4Jt1vAcpXVy6qcEjTswdpipdsN4RSeiztYk4xoqYztPoiqKJgq9nOzuXFnDKrrrMo+5w==")
        dummy_key_data = base64.b64decode("MIICXQIBAAKBgQDCic4kj2kdZxLjW00l8to9hV4+gWAPJFhgvG2Io6pDR/rA1cPAR3Pu4Q4/cwab/gwmCXnnmeQwy3TyzmyCZj9tnBFeNfDsnq0TxoRoTdr0bWv0pGy1uBQ90jZVc85v2whmC9lSigueY4GlR5rOIlNsiuKBWBl/CN/6X3PaYkv04QIDAQABAoGAI2CIGmHyDaTG7I2X9AS752AviVJhs586ay0ZBjYtKlsWoKa/GGJmFNTckHFMjGWgs/IZNyLnOnBlbhpX5UbO1cB7r9Vk1Q3fbIeQdBySyqOG9JfZxd0n4bBSHnopL0naGA0CpSv/tVaUr0BzvNYslw5rcwVinEbGVPP6JNNqbqECQQD1Igbf2qxMHcdEA81qMdExFGmlq61W7gpKtl7XwPhtHIiXyhQsT7M996ZF64EJVg/2/6gQneZ/awJ0Aw8xDkJdAkEAyymWou2v6wPtX+X0hnXnK6OfeEfZGnExE4LpEjNTiQriabvwmCQcgHFBLxKN+C4uVK5HBlHug3jtN0jozSjcVQJBAI+ynLkJJUuRgUhbukTwYyMURkI5+2kkLaBSfBKaKoc73M6uRVkcd4Rx8mS2g3QHoWA3yjvDdGVpQ4ziZjtpknkCQQC2FSsGEYM2Xgm0hlO24xrx+K7nTXWeBk7WzuB3SHsY+yFbZG7I3KySzW5/cuC8yx8JFD1hw7LCMHJitzy3C2UVAkAQGY8PQ9u40krQekUI+imFsPSPdMZqfMKJDLwrXx0mmElUYYZBGtY0q781UYP4GArtwyusDelk6BNjVRjiWUhg")

        self.assertEqual(cert, dummy_cert_data, "p12 cert invalid after extraction")
        self.assertEqual(privkey, dummy_key_data, "p12 key invalid after extraction")

    def test_pkcs12_extract_with_cryptography(self): 
        '''Check if cryptography (unused) can extract pkcs12'''

        # This uses cryptography.hazmat to extract the PKCS data. That's not what the plugin is using right now.

        mock_p12_data = "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"
        mock_p12_password = base64.b64encode(b"1234")

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

    
    def test_Account_activationReplyWithDeclaration(self):
        '''Check if the /Activate reply is stored correctly without XML declaration'''

        # activateDevice used to paste the reply as it is in front of "</activationInfo>". An
        # XML declaration in front of the activationToken then ended up in the middle of
        # activation.xml, and the file never parsed again. A BOM became a stray character.

        import tempfile, shutil

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        mock_activation_xml = b"""<?xml version="1.0"?>
<activationInfo xmlns="http://ns.adobe.com/adept">
  <adept:activationServiceInfo xmlns:adept="http://ns.adobe.com/adept">
    <adept:authURL>https://example.com/auth</adept:authURL>
  </adept:activationServiceInfo>
  <adept:credentials xmlns:adept="http://ns.adobe.com/adept">
    <adept:user>urn:uuid:11111111-2222-3333-4444-555555555555</adept:user>
    <adept:username method="AdobeID">J&#252;rgen</adept:username>
  </adept:credentials>
</activationInfo>
"""

        mock_token = b"""<activationToken xmlns="http://ns.adobe.com/adept">
  <device>urn:uuid:66666666-7777-8888-9999-000000000000</device>
  <fingerprint>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</fingerprint>
  <deviceType>standalone</deviceType>
  <activationURL>https://example.com/activate</activationURL>
  <user>urn:uuid:11111111-2222-3333-4444-555555555555</user>
  <signature>c2lnbmF0dXJl</signature>
</activationToken>"""

        mock_request = """<adept:activate xmlns:adept="http://ns.adobe.com/adept" requestType="initial"><adept:fingerprint>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</adept:fingerprint></adept:activate>"""

        replies = [
            ("no declaration", mock_token),
            ("XML declaration", b'<?xml version="1.0" encoding="UTF-8"?>\n' + mock_token),
            ("BOM", b"\xef\xbb\xbf" + mock_token),
            ("BOM and XML declaration", b'\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8"?>\n' + mock_token + b"\n"),
        ]

        tmp_dir = tempfile.mkdtemp()
        try:
            act_xml_path = os.path.join(tmp_dir, "activation.xml")

            for name, reply in replies:
                with open(act_xml_path, "wb") as f:
                    f.write(mock_activation_xml)
                username = etree.parse(act_xml_path).find("./%s/%s" % (adNS("credentials"), adNS("username"))).text

                with patch.object(libadobe, "FILE_ACTIVATIONXML", act_xml_path), \
                        patch.object(libadobeAccount, "buildActivateReq", return_value=(True, mock_request)), \
                        patch.object(libadobeAccount, "buildActivateReqProxy", return_value=(True, mock_request)), \
                        patch.object(libadobeAccount, "sign_node", return_value="c2lnbmF0dXJl"), \
                        patch.object(libadobeAccount, "sendRequestDocu", return_value=reply):

                    result, _ = libadobeAccount.activateDevice(0, None)
                    self.assertTrue(result, "activateDevice failed (%s)" % name)

                    try:
                        activation = etree.parse(act_xml_path)
                    except etree.XMLSyntaxError as e:
                        self.fail("activation.xml doesn't parse any more (%s): %s" % (name, e))

                    self.assertEqual(activation.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text,
                        "urn:uuid:66666666-7777-8888-9999-000000000000", "activationToken wasn't stored (%s)" % name)
                    self.assertEqual(activation.find("./%s/%s" % (adNS("credentials"), adNS("username"))).text,
                        username, "The existing account data changed (%s)" % name)

                    # For an eReader, activateDevice returns the token, and exportProxyAuth
                    # pastes it into the eReader's activation.xml.
                    result, token = libadobeAccount.activateDevice(0, "proxy data")
                    self.assertTrue(result, "activateDevice failed for an eReader (%s)" % name)
                    self.assertTrue(token.startswith(b"<activationToken"), "The token for an eReader still has what the reply had in front of it (%s)" % name)
                    self.assertEqual(etree.fromstring(token).find(adNS("device")).text,
                        "urn:uuid:66666666-7777-8888-9999-000000000000", "Wrong token for an eReader (%s)" % name)
        finally:
            shutil.rmtree(tmp_dir)

    def test_Account_activationRequestNonASCII(self):
        '''Check if a signed activation request with non-ASCII text reaches the server as it was signed'''

        # activateDevice used to decode the request's UTF-8 serialization as Latin-1, and
        # sendRequestDocu then encoded that as UTF-8 again. Non-ASCII text arrived encoded
        # twice, so it no longer matched the signature.

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        mock_request = """<adept:activate xmlns:adept="http://ns.adobe.com/adept" requestType="initial"><adept:fingerprint>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</adept:fingerprint><adept:deviceType>Leseger&#228;t</adept:deviceType></adept:activate>"""
        device_type = etree.fromstring(mock_request).find(adNS("deviceType")).text

        signed_hashes = []
        def mock_sign_node(node, prefer_bytebooks):
            signed_hashes.append(libadobe.hash_node(node).hexdigest())
            return "c2lnbmF0dXJl"

        sent_data = []
        def mock_send(URL, document, contenttype, returnRC = False, validate_tls = True):
            # What would go over the network
            sent_data.append(document)
            return b'<error xmlns="http://ns.adobe.com/adept" data="E_TEST_ONLY"/>'

        with patch.object(libadobeAccount, "buildActivateReq", return_value=(True, mock_request)), \
                patch.object(libadobeAccount, "sign_node", side_effect=mock_sign_node), \
                patch.object(libadobe, "sendPOSTHTTPRequest", side_effect=mock_send):
            result, msg = libadobeAccount.activateDevice(0, None)

        self.assertFalse(result, "activateDevice should return the mocked server error")
        self.assertEqual(len(sent_data), 1, "activateDevice didn't send the request")

        # The server parses the request as UTF-8 and checks the signature against its hash
        received = etree.fromstring(sent_data[0])
        self.assertEqual(received.find(adNS("deviceType")).text, device_type, "The server gets different text than what was signed")
        self.assertEqual(libadobe.hash_node(received).hexdigest(), signed_hashes[0], "The signature doesn't match the request the server gets")

    def test_writeFilesAtomically(self):
        '''Check if account files are replaced completely or not at all'''

        # When managing an activation, we need to write multiple files. 
        # If only some of them get written and some don't, then the activation
        # is corrupted. Ensure that that's not going to happen.

        import tempfile, shutil, errno, stat

        tmp_dir = tempfile.mkdtemp()
        try:
            path_a = os.path.join(tmp_dir, "activation.xml")
            path_b = os.path.join(tmp_dir, "device.xml")
            with open(path_a, "wb") as f:
                f.write(b"old a")
            if sys.platform != "win32":
                os.chmod(path_a, 0o640)

            # One existing and one new file
            libadobe.write_files_atomically([(path_a, b"new a"), (path_b, b"new b")])
            for path, content in [(path_a, b"new a"), (path_b, b"new b")]:
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), content, "%s wasn't written" % (os.path.basename(path)))
            if sys.platform != "win32":
                self.assertEqual(stat.S_IMODE(os.stat(path_a).st_mode), 0o640, "The file's permissions changed")

            # A full disk while writing the second file leaves both files as they were
            real_fsync = os.fsync
            fsync_calls = []
            def failing_fsync(fd):
                fsync_calls.append(fd)
                if len(fsync_calls) == 2:
                    raise OSError(errno.ENOSPC, "No space left on device")
                return real_fsync(fd)

            with patch.object(os, "fsync", side_effect=failing_fsync):
                self.assertRaises(OSError, libadobe.write_files_atomically, [(path_a, b"newer a"), (path_b, b"newer b")])
            for path, content in [(path_a, b"new a"), (path_b, b"new b")]:
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), content, "%s changed although writing failed" % (os.path.basename(path)))

            # A symlink to an account file stays a symlink
            if hasattr(os, "symlink") and sys.platform != "win32":
                real_path = os.path.join(tmp_dir, "real.xml")
                link_path = os.path.join(tmp_dir, "link.xml")
                with open(real_path, "wb") as f:
                    f.write(b"old")
                os.symlink(real_path, link_path)
                libadobe.write_file_atomically(link_path, b"new")
                self.assertTrue(os.path.islink(link_path), "The symlink was replaced by a file")
                with open(real_path, "rb") as f:
                    self.assertEqual(f.read(), b"new", "The symlink's target wasn't written")
                os.remove(link_path)
                os.remove(real_path)

            # No temporary files are left behind
            self.assertEqual(sorted(os.listdir(tmp_dir)), ["activation.xml", "device.xml"], "Temporary files are left behind")
        finally:
            shutil.rmtree(tmp_dir)


    def test_Account_loginCredentialEncryption(self):
        '''Check if we can properly encrypt login credentials (ASCII)'''

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

        self.assertEqual(binascii.hexlify(msg), b'f87afc8c7525dc4b83ec0ce2ab4bef5108757365726e616d6512756e69742d746573742d70617373776f7264', "devkey encryption returned wrong result")

    def test_Account_loginCredentialEncryptionWithUTF8(self):
        '''Check if we can properly encrypt login credentials (UTF-8)'''

        # This cert is not the actual Adobe auth cert. 
        # I added a fake one in here so we can also test if the encrypted data is valid
        # by just decrypting it again.
        # Also, I don't think I'd be allowed to redistribute the Adobe cert anyways.
        mock_auth_certificate = "MIICLjCCAZegAwIBAgIUPo11NtzZuIdqNySSJhG9ntZEpy0wDQYJKoZIhvcNAQEFBQAwKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMB4XDTIxMTIxODIwNDYwMVoXDTIxMTIyODIwNDYwMVowKTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEURlQUNTTSB1bml0IHRlc3RzMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/NkUXHTEYAyQzm6BHekzyAM8EfjBvWCLAvOVBs/eTqKwrOfqkuT+TuIYfvBx/GuWx9szMi/sTL1R0vCLxhO6FxnZH+OW4OC8mi5oyfWQxiZe41Mo7o6FYnyMA+fuwz9TyeL2BmObH9HewVhTwmVesdTNOAwaH+neC/IJ5/yGDMwIDAQABo1MwUTAdBgNVHQ4EFgQUYlO/CiLaNR2Mlmg64KALHq3jq18wHwYDVR0jBBgwFoAUYlO/CiLaNR2Mlmg64KALHq3jq18wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQAzF75pKA2lzNxM+kPWErvJmOmP1aAWGZfbAG7naiC32pPHwNfKjUTQ1vpqoYxydvsmHzVhF1Z/czBdLMR8/PtSv+cGrhhLrc7c5uzp2YDZU4TiGaGz7jiD5C0rp3IpyEP3IN0SNeYwEZtKMph+pv3k5zcgsIPOsHIS0gwV3U70HA=="
        mock_auth_cert_private_key = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWEFJQkFBS0JnUUMvTmtVWEhURVlBeVF6bTZCSGVrenlBTThFZmpCdldDTEF2T1ZCcy9lVHFLd3JPZnFrCnVUK1R1SVlmdkJ4L0d1V3g5c3pNaS9zVEwxUjB2Q0x4aE82RnhuWkgrT1c0T0M4bWk1b3lmV1F4aVplNDFNbzcKbzZGWW55TUErZnV3ejlUeWVMMkJtT2JIOUhld1ZoVHdtVmVzZFROT0F3YUgrbmVDL0lKNS95R0RNd0lEQVFBQgpBb0dBSUxCaWQyVWlNM3kxLzZ5blpoRGVmckRzczFQdmE5bWhkMW5UeDd2QW81bStkVlZnS0RFVFVXbkdaRDZBCmtLcEVnbnd5M3ZVL1l6UkFPQVRCNUpCWlJuSEpzeHBmUk9sVHBZRHJBaXFoZ0dlZGNkSHozb1NhSk8zZVVZNzcKUEt6NDZ0VTNUTVZvMFdndmV0d3FKWXNEencxcHREa2Nqb2xxVGNYSWxhdTBGYUVDUVFEbERTTnNzWTM2VmlzSwpma0hNblJEd1FJdHFPNGlrZEtFRGNqTzU0Q3RXYVpjK2lGZ1FsMjFzUk1ueW91SVBzT3RBTG96V0wwMzJ2NTRHCk5XQUI1emkvQWtFQTFiVndJV1lzeVh6aHp5Wko4bWhmTGYvY2kydmQyY2RTK3lBTEwrbUpJQmJSejMvNFdHSFgKdUxXMWwxWGVLYWVmRnFob1JpTzdxUWpNWCthb3ZqYytqUUpCQU1TQ2F4djdrTlZ2UytucXZFVHhrL0NyVDNESwp0c1p4RVJyRnhiNzRwZld6RFlFbXRIYzNremRLSlFBMzRqNllDSnk5MHpLR3p4cWM5dFJZd28rZmNqMENRRWptCmY3Mms4Um82YzMwS2ZxY21XM0dCbW1ZbEFhVE1qYzRFZkV4M3ljTWNoYTNXNVl5Z3M4bmFrbnR4V3p1eVpsNkEKVERIQTlyOE90VWp4a2haeEdmRUNRRndVZlhEVncwNjlOaUdJRUpWRWVTRkp6TCszb1JSWCsrZ0krb3AwNlRBaApCcTFjemVZMWFOMllTWGIveDZ4TEI5amFYSXg1UElIM1Uyc3VhZHdETnNVPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="

        user = "username"
        passwd = u"unit-test-¶Āssword🜂"

        # P = ¶ = U+00B6
        # A = Ā = U+0100
        # Triangle = 🜂 = U+1F702

        libadobe.devkey_bytes = bytearray([0xf8, 0x7a, 0xfc, 0x8c, 0x75, 0x25, 0xdc, 0x4b, 0x83, 0xec, 0x0c, 0xe2, 0xab, 0x4b, 0xef, 0x51])
        encrypted = libadobeAccount.encryptLoginCredentials(user, passwd, mock_auth_certificate)

        # Okay, now try to decrypt this again: 

        pkey = RSA.import_key(base64.b64decode(mock_auth_cert_private_key))
        cipher_engine = PKCS1_v1_5.new(pkey)
        msg = cipher_engine.decrypt(encrypted, bytes([0x00] * 16))

        self.assertEqual(binascii.hexlify(msg), b'f87afc8c7525dc4b83ec0ce2ab4bef5108757365726e616d6518756e69742d746573742dc2b6c4807373776f7264f09f9c82', "devkey encryption returned wrong result")

