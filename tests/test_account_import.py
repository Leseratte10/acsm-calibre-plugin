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
if sys.version_info[0] >= 3:
    from unittest.mock import patch
else: 
    from mock import patch
from lxml import etree

try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES               # type: ignore


from acsm_input import libadobe             # type: ignore
from acsm_input import libadobeFulfill      # type: ignore
from acsm_input import libadobeImportAccount    # type: ignore


def encrypt_license_key(key, master_key, fingerprint):
    '''Encrypts a privateLicenseKey the way ADE stores it in the registry: AES-CBC with the
    master key, the first 16 bytes of the fingerprint as IV, and PKCS#7 padding'''
    pad = 16 - len(key) % 16
    aes = AES.new(master_key, AES.MODE_CBC, base64.b64decode(fingerprint)[:16])
    return base64.b64encode(aes.encrypt(key + bytes(bytearray([pad] * pad)))).decode("ascii")


class TestAccountImport(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_importMixedByteBooksFlags(self):
        '''Check if importing works with Adobe entries without the ofByteBooks flag (both orders)'''

        # Entries without the ofByteBooks flag count as Adobe, so they have to end up
        # next to the ByteBooks entry of the same name, no matter which one comes first.

        libadobeImportAccount.persistent_data = dict()
        libadobeImportAccount.handle_subkey("credentials", "pkcs12", "ADOBE", None, None, None, None)
        libadobeImportAccount.handle_subkey("credentials", "pkcs12", "BB", None, None, True, None)
        self.assertEqual(libadobeImportAccount.persistent_data, {"credentials": {"pkcs12": {False: "ADOBE", True: "BB"}}},
                         "Unflagged entry followed by ByteBooks entry imported incorrectly")

        libadobeImportAccount.persistent_data = dict()
        libadobeImportAccount.handle_subkey("credentials", "pkcs12", "BB", None, None, True, None)
        libadobeImportAccount.handle_subkey("credentials", "pkcs12", "ADOBE", None, None, None, None)
        self.assertEqual(libadobeImportAccount.persistent_data, {"credentials": {"pkcs12": {False: "ADOBE", True: "BB"}}},
                         "ByteBooks entry followed by unflagged entry imported incorrectly")

        # Keys that never have a flag must stay plain values
        libadobeImportAccount.persistent_data = dict()
        libadobeImportAccount.handle_subkey("credentials", "user", "urn:uuid:1234", None, None, None, None)
        self.assertEqual(libadobeImportAccount.persistent_data, {"credentials": {"user": "urn:uuid:1234"}},
                         "Unflagged entry without ByteBooks counterpart imported incorrectly")


    def test_importWineRegistryMixedByteBooksFlags(self):
        '''Check if a Wine registry with mixed ofByteBooks flags is imported correctly'''

        import tempfile, shutil

        fingerprint = base64.b64encode(bytes(bytearray([0x01] * 20))).decode("ascii")
        private_license_key = encrypt_license_key(bytes(bytearray(32)), bytes(bytearray([0x02] * 16)), fingerprint)

        # (registry key name, list of (name, value, ofByteBooks flag or None))
        activation = [
            ("activationServiceInfo", [
                ("authURL", "https://auth.example.com/adept", None),
                ("userInfoURL", "https://userinfo.example.com/adept", None),
                ("activationURL", "https://activate.example.com/adept", None),
                ("certificate", "ASI_CERT_BB", "true"),
                ("certificate", "ASI_CERT_ADOBE", None),
                ("authenticationCertificate", "ASI_AUTH_ADOBE", None),
                ("authenticationCertificate", "ASI_AUTH_BB", "true"),
            ]),
            ("credentials", [
                ("user", "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa", None),
                ("pkcs12", "P12_ADOBE", None),
                ("pkcs12", "P12_BB", "true"),
                ("licenseCertificate", "LIC_BB", "true"),
                ("licenseCertificate", "LIC_ADOBE", None),
                ("privateLicenseKey", private_license_key, None),
                ("authenticationCertificate", "AUTH_ADOBE", None),
                ("authenticationCertificate", "AUTH_BB", "true"),
            ]),
            ("activationToken", [
                ("device", "urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84", None),
                ("fingerprint", fingerprint, None),
                ("deviceType", "standalone", None),
                ("activationURL", "https://activate.example.com/adept", None),
                ("user", "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa", None),
                ("signature", "SIGNATURE", None),
            ]),
        ]

        # Build user.reg the way Wine writes it: a blank line before every key, parents before children.
        prefix = "Software\\\\ByteBooks\\\\Adept\\\\Activation\\\\"
        reg = "WINE REGISTRY Version 2\n;; All keys relative to \\\\User\\\\S-1-5-21-0-0-0-1000\n"
        for i, (parent, children) in enumerate(activation):
            reg += "\n[%s%04d] 1700000000\n#time=1d9000000000000\n@=\"%s\"\n" % (prefix, i, parent)
            for j, (name, value, flag) in enumerate(children):
                reg += "\n[%s%04d\\\\%04d] 1700000000\n#time=1d9000000000000\n@=\"%s\"\n" % (prefix, i, j, name)
                if flag is not None:
                    reg += "\"ofByteBooks\"=\"%s\"\n" % (flag)
                reg += "\"value\"=\"%s\"\n" % (value)
        reg += "\n[Software\\\\ByteBooks\\\\Adept\\\\Device] 1700000000\n#time=1d9000000000000\n"

        temp_dir = tempfile.mkdtemp()
        try:
            wine_prefix = os.path.join(temp_dir, "wineprefix")
            account_dir = os.path.join(temp_dir, "account")
            os.mkdir(wine_prefix)
            os.mkdir(account_dir)

            f = open(os.path.join(wine_prefix, "user.reg"), "w")
            f.write(reg)
            f.close()

            libadobe.update_account_path(account_dir)

            with patch("acsm_input.getEncryptionKeyLinux.GetMasterKey", return_value=bytes(bytearray([0x02] * 16))):
                success, msg = libadobeImportAccount.importADEactivationLinuxWine(wine_prefix)

            self.assertTrue(success, "Wine import failed: %s" % (msg))

            adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
            activationxml = etree.parse(os.path.join(account_dir, "activation.xml"))

            def entries(path):
                return sorted((e.get("ofByteBooks"), e.text) for e in activationxml.findall(path))

            asi = "./%s/" % (adNS("activationServiceInfo"))
            cred = "./%s/" % (adNS("credentials"))

            self.assertEqual(entries(asi + adNS("certificate")), [("false", "ASI_CERT_ADOBE"), ("true", "ASI_CERT_BB")], "activationServiceInfo certificate imported incorrectly")
            self.assertEqual(entries(asi + adNS("authenticationCertificate")), [("false", "ASI_AUTH_ADOBE"), ("true", "ASI_AUTH_BB")], "activationServiceInfo authenticationCertificate imported incorrectly")
            self.assertEqual(entries(cred + adNS("pkcs12")), [("false", "P12_ADOBE"), ("true", "P12_BB")], "pkcs12 imported incorrectly")
            self.assertEqual(entries(cred + adNS("licenseCertificate")), [("false", "LIC_ADOBE"), ("true", "LIC_BB")], "licenseCertificate imported incorrectly")
            self.assertEqual(entries(cred + adNS("authenticationCertificate")), [("false", "AUTH_ADOBE"), ("true", "AUTH_BB")], "authenticationCertificate imported incorrectly")

            self.assertEqual(libadobeFulfill.getAvailableCertTypes(), (True, True), "Imported activation doesn't contain both certificate sets")
            self.assertEqual(activationxml.find(cred + adNS("privateLicenseKey")).text, base64.b64encode(bytes(bytearray(32))).decode("ascii"),
                             "privateLicenseKey decrypted incorrectly")

        finally:
            libadobe.update_account_path("")
            shutil.rmtree(temp_dir, ignore_errors=True)


    def test_importWrongEncryptionKey(self):
        '''Check if the import fails if the encryption key doesn't decrypt the private license key'''

        # The padding used to be removed without checking it, so with the wrong key (for instance
        # the one of the other vendor) the import stored garbage as the key and reported success.

        fingerprint = base64.b64encode(bytes(bytearray([0x01] * 20))).decode("ascii")
        libadobeImportAccount.persistent_data = {
            "credentials": {"privateLicenseKey": encrypt_license_key(bytes(bytearray(32)), bytes(bytearray([0x02] * 16)), fingerprint)},
            "activationToken": {"fingerprint": fingerprint},
        }
        success, msg = libadobeImportAccount.handle_subkey(None, None, None, bytes(bytearray([0x03] * 16)), None, None, None)
        self.assertFalse(success, "Import with the wrong encryption key should fail")
        self.assertIn("Could not decrypt the private license key", msg)

    def test_importWineRegistryEscapes(self):
        '''Check if the Wine import decodes the escapes in Wine's user.reg'''

        # Wine stores every character above 127 as \x and up to four hex digits, and escapes
        # backslashes, quotes and control characters. The import used to take the strings as
        # they were, so an umlaut in an ID ended up as \xfc in activation.xml.

        import tempfile, shutil

        # Strings as they are in user.reg, and what they stand for
        cases = [
            ("plain text", u"plain text"),
            (r"j\xfcrgen", b"j\xc3\xbcrgen".decode("utf-8")),           # as few hex digits as needed ...
            (r"b\x00e4cker", b"b\xc3\xa4cker".decode("utf-8")),         # ... and four if a hex digit follows
            (r"\xd83d\xde00", b"\xf0\x9f\x98\x80".decode("utf-8")),     # a UTF-16 surrogate pair
            (r"a\\b \"c\"", u'a\\b "c"'),
            (r"\t\n\r\a\b\e\f\v", u"\t\n\r\a\b\x1b\f\v"),
            (r"\1x\0012", u"\x01x\x012"),                               # octal escapes
            (r"\xq \[\]", u"xq []"),                                    # anything else stands for itself
        ]
        for escaped, expected in cases:
            self.assertEqual(libadobeImportAccount.decode_wine_registry_string(escaped), expected, "Wrong result for %r" % (escaped))

        # A whole import, with a username and method that contain escapes
        fingerprint = base64.b64encode(bytes(bytearray([0x01] * 20))).decode("ascii")
        private_license_key = encrypt_license_key(bytes(bytearray(32)), bytes(bytearray([0x02] * 16)), fingerprint)

        # (registry key name, list of (name, value, method or None)), values escaped like in user.reg
        activation = [
            ("activationServiceInfo", [
                ("authURL", "https://auth.example.com/adept", None),
                ("userInfoURL", "https://userinfo.example.com/adept", None),
                ("activationURL", "https://activate.example.com/adept", None),
                ("certificate", "ASI_CERT", None),
                ("authenticationCertificate", "ASI_AUTH", None),
            ]),
            ("credentials", [
                ("user", "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa", None),
                ("username", r"j\xfcrgen.b\x00e4cker@example.de", r"H\xe4ndler"),
                ("pkcs12", "P12", None),
                ("licenseCertificate", "LIC", None),
                ("privateLicenseKey", private_license_key, None),
                ("authenticationCertificate", "AUTH", None),
            ]),
            ("activationToken", [
                ("device", "urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84", None),
                ("fingerprint", fingerprint, None),
                ("deviceType", "standalone", None),
                ("activationURL", "https://activate.example.com/adept", None),
                ("user", "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa", None),
                ("signature", "SIGNATURE", None),
            ]),
        ]

        prefix = "Software\\\\Adobe\\\\Adept\\\\Activation\\\\"
        reg = "WINE REGISTRY Version 2\n;; All keys relative to \\\\User\\\\S-1-5-21-0-0-0-1000\n"
        for i, (parent, children) in enumerate(activation):
            reg += "\n[%s%04d] 1700000000\n#time=1d9000000000000\n@=\"%s\"\n" % (prefix, i, parent)
            for j, (name, value, method) in enumerate(children):
                reg += "\n[%s%04d\\\\%04d] 1700000000\n#time=1d9000000000000\n@=\"%s\"\n" % (prefix, i, j, name)
                if method is not None:
                    reg += "\"method\"=\"%s\"\n" % (method)
                reg += "\"value\"=\"%s\"\n" % (value)
        reg += "\n[Software\\\\Adobe\\\\Adept\\\\Device] 1700000000\n#time=1d9000000000000\n"

        temp_dir = tempfile.mkdtemp()
        try:
            wine_prefix = os.path.join(temp_dir, "wineprefix")
            account_dir = os.path.join(temp_dir, "account")
            os.mkdir(wine_prefix)
            os.mkdir(account_dir)

            f = open(os.path.join(wine_prefix, "user.reg"), "w")
            f.write(reg)
            f.close()

            libadobe.update_account_path(account_dir)

            with patch("acsm_input.getEncryptionKeyLinux.GetMasterKey", return_value=bytes(bytearray([0x02] * 16))):
                success, msg = libadobeImportAccount.importADEactivationLinuxWine(wine_prefix)
            self.assertTrue(success, "Wine import failed: %s" % (msg))

            adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
            username = etree.parse(os.path.join(account_dir, "activation.xml")).find("./%s/%s" % (adNS("credentials"), adNS("username")))
            self.assertEqual(username.text, b"j\xc3\xbcrgen.b\xc3\xa4cker@example.de".decode("utf-8"), "Username imported with Wine's escapes")
            self.assertEqual(username.get("method"), b"H\xc3\xa4ndler".decode("utf-8"), "Method imported with Wine's escapes")

        finally:
            libadobe.update_account_path("")
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_wineHelperOutputIsChecked(self):
        '''Check if the Wine key helper's output is only accepted if it's a 16-byte key'''

        # GetMasterKey used to accept anything from a helper that exited with 0, so empty or
        # broken output only failed later, with a misleading error about the registry.

        import tempfile, shutil, binascii
        from acsm_input import getEncryptionKeyLinux      # type: ignore

        try:
            # Python 2: print() writes byte strings there, which io.StringIO doesn't accept.
            from StringIO import StringIO  # type: ignore
        except ImportError:
            from io import StringIO

        class MockProcess(object):
            def __init__(self, stdout, returncode):
                self.stdout = stdout
                self.returncode = returncode
            def communicate(self):
                return self.stdout, b"Using the Adobe device key\n"

        key = bytes(bytearray(range(16)))
        cases = [
            ("a 16-byte key", binascii.hexlify(key), 0, key),
            ("a 16-byte key and a line break", binascii.hexlify(key) + b"\r\n", 0, key),
            ("no output", b"", 0, None),
            ("an 8-byte key", binascii.hexlify(key[:8]), 0, None),
            ("a 32-byte key", binascii.hexlify(key * 2), 0, None),
            ("an odd number of hex digits", binascii.hexlify(key)[:-1], 0, None),
            ("an error message", b"Error: something went wrong", 0, None),
            ("an error exit code", binascii.hexlify(key), 1, None),
        ]

        wine_prefix = tempfile.mkdtemp()
        try:
            for label, stdout, returncode, expected in cases:
                # GetMasterKey logs every step, keep that out of the test output.
                old_stdout, old_stderr = sys.stdout, sys.stderr
                sys.stdout, sys.stderr = StringIO(), StringIO()
                try:
                    with patch("subprocess.Popen", return_value=MockProcess(stdout, returncode)):
                        master_key = getEncryptionKeyLinux.GetMasterKey(wine_prefix)
                finally:
                    sys.stdout, sys.stderr = old_stdout, old_stderr
                self.assertEqual(master_key, expected, "Wrong result for %s" % (label))
        finally:
            shutil.rmtree(wine_prefix)

    def test_importWineKeySourceMatchesActivation(self):
        '''Check if the Wine key helper is asked for the device key of the imported activation'''

        import tempfile, shutil

        try:
            from unittest.mock import call
        except ImportError:
            from mock import call

        # (activation trees in user.reg, expected use_bytebooks argument for GetMasterKey)
        cases = [
            (["Adobe"], False),
            (["ByteBooks"], True),
            (["Adobe", "ByteBooks"], True),
        ]

        for vendors, expected in cases:
            temp_dir = tempfile.mkdtemp()
            try:
                reg = "WINE REGISTRY Version 2\n"
                for vendor in vendors:
                    reg += "\n[Software\\\\%s\\\\Adept\\\\Activation\\\\0000] 1700000000\n@=\"credentials\"\n" % (vendor)

                f = open(os.path.join(temp_dir, "user.reg"), "w")
                f.write(reg)
                f.close()

                # Without a key the import stops right after asking for it, which is all this test needs.
                with patch("acsm_input.getEncryptionKeyLinux.GetMasterKey", return_value=None) as get_master_key:
                    success, msg = libadobeImportAccount.importADEactivationLinuxWine(temp_dir)

                self.assertFalse(success, "Import without a device key should fail")
                self.assertEqual(get_master_key.call_args_list, [call(temp_dir, expected)],
                                 "Wrong device key requested for activation trees %s" % (vendors))
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

