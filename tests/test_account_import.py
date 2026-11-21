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



import libadobe             # type: ignore
import libadobeFulfill      # type: ignore
import libadobeImportAccount    # type: ignore


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
        private_license_key = base64.b64encode(bytes(bytearray(32))).decode("ascii")

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

            with patch("getEncryptionKeyLinux.GetMasterKey", return_value=bytes(bytearray([0x02] * 16))):
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

        finally:
            libadobe.update_account_path("")
            shutil.rmtree(temp_dir, ignore_errors=True)


