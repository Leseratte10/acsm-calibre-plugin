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
from acsm_input.customRSA import CustomRSA # type: ignore


class FakeResponse(object):
    '''What urlopen() returns for a server that replies with body'''

    def __init__(self, body):
        self.body = body

    def getcode(self):
        return 200

    def read(self):
        return self.body

    def close(self):
        pass


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

        # Python 3.13 turns on its strict X.509 checks by default. The plugin turns them off.
        strict = int(ssl.VERIFY_X509_STRICT)
        self.assertFalse(int(ctx.verify_flags) & strict, "validate_tls=True uses the strict X.509 checks")


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

    def test_removePadding(self):
        '''Check if the PKCS#7 padding is checked before it's removed, like in customcrypto'''

        self.assertEqual(libadobe.remove_padding(b"hello" + b"\x0b" * 11), b"hello")
        self.assertEqual(libadobe.remove_padding(b"\x10" * 16), b"")

        # Garbage from a wrong key: an empty result, a padding byte that doesn't match,
        # a padding length of 0, and one larger than the AES block size
        for data in (b"", b"hello" + b"\x0a" + b"\x0b" * 10, b"hello" + b"\x0b" * 10 + b"\x00", b"\x11" * 16):
            self.assertRaises(ValueError, libadobe.remove_padding, data)

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
            import rsa  # type: ignore
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

   
    def test_findVendorValues(self):
        '''Check if ByteBooks and Adobe values are told apart correctly'''

        xml = etree.fromstring("""<root xmlns="http://ns.adobe.com/adept">
  <both><v ofByteBooks="true">BB</v><v ofByteBooks="false">AD</v></both>
  <unflagged><v>AD</v></unflagged>
  <bytebooks><v ofByteBooks="true">BB</v></bytebooks>
  <first><v>AD1</v><v ofByteBooks="false">AD2</v><v ofByteBooks="true">BB1</v><v ofByteBooks="true">BB2</v></first>
  <empty><v ofByteBooks="true"/><v ofByteBooks="true">BB</v><v></v><v>AD</v></empty>
  <otherflag><v ofByteBooks="TRUE">X</v><v ofByteBooks="1">Y</v></otherflag>
  <none/>
</root>""")

        cases = [
            # Activations from ADE and older plugin versions have no ofByteBooks flag, that's Adobe
            ("both", ("BB", "AD")),
            ("unflagged", (None, "AD")),
            ("bytebooks", ("BB", None)),
            # The first value of each vendor
            ("first", ("BB1", "AD1")),
            # Elements without text don't count
            ("empty", ("BB", "AD")),
            # Neither vendor
            ("otherflag", (None, None)),
            ("none", (None, None)),
        ]

        for parent, expected in cases:
            self.assertEqual(libadobe.find_vendor_values(xml, parent, "v"), expected, "Wrong values for <%s>" % (parent))

        # The tags are a path from the parent, so <v> elements further down don't count
        self.assertEqual(libadobe.find_vendor_values(xml, "v"), (None, None), "Found values that aren't children of the parent")


    def test_preferVendor(self):
        '''Check if the preferred vendor's value is chosen, with the other one as fallback'''

        # (ByteBooks value, Adobe value, prefer_bytebooks, expected)
        cases = [
            ("BB", "AD", True, ("BB", True)),
            ("BB", "AD", False, ("AD", False)),
            ("BB", None, False, ("BB", True)),
            (None, "AD", True, ("AD", False)),
            (None, None, True, (None, None)),
            (None, None, False, (None, None)),
        ]

        for bytebooks, adobe, prefer_bytebooks, expected in cases:
            self.assertEqual(libadobe.prefer_vendor(bytebooks, adobe, prefer_bytebooks), expected,
                             "Wrong choice for %r, %r, prefer_bytebooks=%s" % (bytebooks, adobe, prefer_bytebooks))



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
                        patch.object(libadobe.ulib, "urlopen", return_value=FakeResponse(reply)):

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
        # sending it encoded that as UTF-8 again. Non-ASCII text arrived encoded
        # twice, so it no longer matched the signature.

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        mock_request = """<adept:activate xmlns:adept="http://ns.adobe.com/adept" requestType="initial"><adept:fingerprint>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</adept:fingerprint><adept:deviceType>Leseger&#228;t</adept:deviceType></adept:activate>"""
        device_type = etree.fromstring(mock_request).find(adNS("deviceType")).text

        signed_hashes = []
        def mock_sign_node(node, prefer_bytebooks):
            signed_hashes.append(libadobe.hash_node(node).hexdigest())
            return "c2lnbmF0dXJl"

        sent_data = []
        def mock_urlopen(request, **kwargs):
            # What would go over the network
            sent_data.append(request.data)
            return FakeResponse(b'<error xmlns="http://ns.adobe.com/adept" data="E_TEST_ONLY"/>')

        with patch.object(libadobeAccount, "buildActivateReq", return_value=(True, mock_request)), \
                patch.object(libadobeAccount, "sign_node", side_effect=mock_sign_node), \
                patch.object(libadobe.ulib, "urlopen", side_effect=mock_urlopen):
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

