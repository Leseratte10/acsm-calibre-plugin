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


FINGERPRINT = base64.b64encode(bytes(bytearray([0x01] * 20))).decode("ascii")
DEVICE_KEYS = {False: bytes(bytearray([0x02] * 16)), True: bytes(bytearray([0x03] * 16))}     # ADE, BDE


def complete_activation(is_bytebooks):
    '''An activation with every value the import needs, as a list of (parent, [(name, value, method,
    ofByteBooks)]) for the registry keys Activation\\0000, \\0001 and so on. Its private license key
    is encrypted with the device key of that vendor and decrypts to 32 zero bytes.'''
    user = "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa"
    return [
        ("activationServiceInfo", [
            ("authURL", "https://auth.example.com/adept", None, None),
            ("userInfoURL", "https://userinfo.example.com/adept", None, None),
            ("activationURL", "https://activate.example.com/adept", None, None),
            ("certificate", "ASI_CERT", None, None),
            ("authenticationCertificate", "ASI_AUTH", None, None),
        ]),
        ("credentials", [
            ("user", user, None, None),
            ("pkcs12", "P12", None, None),
            ("licenseCertificate", "LIC", None, None),
            ("privateLicenseKey", encrypt_license_key(bytes(bytearray(32)), DEVICE_KEYS[is_bytebooks], FINGERPRINT), None, None),
            ("authenticationCertificate", "AUTH", None, None),
        ]),
        ("activationToken", [
            ("device", "urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84", None, None),
            ("fingerprint", FINGERPRINT, None, None),
            ("deviceType", "standalone", None, None),
            ("activationURL", "https://activate.example.com/adept", None, None),
            ("user", user, None, None),
            ("signature", "SIGNATURE", None, None),
        ]),
    ]


def wine_registry(trees):
    '''The text of a user.reg with an activation for each {is_bytebooks: list of keys} in trees,
    see complete_activation(). A key that is None is left out.'''
    reg = "WINE REGISTRY Version 2\n"
    for is_bytebooks in sorted(trees):
        prefix = "Software\\\\%s\\\\Adept\\\\Activation\\\\" % ("ByteBooks" if is_bytebooks else "Adobe")
        for i, key in enumerate(trees[is_bytebooks]):
            if key is None:
                continue
            parent, children = key
            reg += "\n[%s%04d] 1700000000\n@=\"%s\"\n" % (prefix, i, parent)
            for j, (name, value, method, ofbytebooks) in enumerate(children):
                reg += "\n[%s%04d\\\\%04d] 1700000000\n@=\"%s\"\n" % (prefix, i, j, name)
                if method is not None:
                    reg += "\"method\"=\"%s\"\n" % (method)
                if ofbytebooks is not None:
                    reg += "\"ofByteBooks\"=\"%s\"\n" % (ofbytebooks)
                reg += "\"value\"=\"%s\"\n" % (value)
    return reg + "\n"


def import_from_windows_registry(trees, unnamed_keys=()):
    '''Runs importADEactivationWindows() on a fake registry with an activation for each
    {is_bytebooks: list of keys} in trees (see complete_activation(), None leaves a key out).
    unnamed_keys are key paths below Software\\ that have no default value, so no name.
    Returns (success, message, vendors whose device key was requested, activation.xml or None).'''

    import tempfile, shutil, types

    registry = {}       # key path -> (default value, other values)
    for is_bytebooks, keys in trees.items():
        root = "Software\\%s\\Adept\\Activation" % ("ByteBooks" if is_bytebooks else "Adobe")
        registry[root] = (None, {})
        for i, key in enumerate(keys):
            if key is None:
                continue
            parent, children = key
            registry["%s\\%04d" % (root, i)] = (parent, {})
            for j, (name, value, method, ofbytebooks) in enumerate(children):
                values = {"value": value}
                if method is not None:
                    values["method"] = method
                if ofbytebooks is not None:
                    values["ofByteBooks"] = ofbytebooks
                registry["%s\\%04d\\%04d" % (root, i, j)] = (name, values)
    for path in unnamed_keys:
        registry["Software\\" + path] = (None, registry["Software\\" + path][1])

    class FakeWinreg(object):
        HKEY_CURRENT_USER = None

        @staticmethod
        def OpenKey(key, sub_key):
            path = sub_key if key is None else key + "\\" + sub_key
            if path not in registry:
                raise OSError("No such key: " + path)
            return path

        @staticmethod
        def QueryValueEx(key, name):
            default, values = registry[key]
            value = default if name is None else values.get(name)
            if value is None:
                raise OSError("No such value: %s" % (name))
            return value, 1

    # The import checks calibre.constants.iswindows, gets the key from getEncryptionKeyWindows
    calibre = types.ModuleType("calibre")
    calibre.constants = types.ModuleType("calibre.constants")
    calibre.constants.iswindows = True
    key_module = types.ModuleType("getEncryptionKeyWindows")
    key_requests = []
    key_module.GetMasterKey = lambda use_bytebooks: key_requests.append(use_bytebooks) or DEVICE_KEYS[use_bytebooks]
    fake_modules = {"calibre": calibre, "calibre.constants": calibre.constants, "winreg": FakeWinreg,
                    "_winreg": FakeWinreg, "acsm_input.getEncryptionKeyWindows": key_module}

    account_dir = tempfile.mkdtemp()
    try:
        libadobe.update_account_path(account_dir)
        with patch.dict(sys.modules, fake_modules):
            success, msg = libadobeImportAccount.importADEactivationWindows()
        path = os.path.join(account_dir, "activation.xml")
        activationxml = etree.parse(path) if os.path.exists(path) else None
        return success, msg, key_requests, activationxml
    finally:
        libadobe.update_account_path("")
        shutil.rmtree(account_dir, ignore_errors=True)


class TestAccountImport(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_importMixedByteBooksFlags(self):
        '''Check if importing works with Adobe entries without the ofByteBooks flag (both orders)'''

        # Entries without the ofByteBooks flag count as Adobe, so they have to end up
        # next to the ByteBooks entry of the same name, no matter which one comes first.

        adobe = ("credentials", "pkcs12", "ADOBE", None, None)
        bytebooks = ("credentials", "pkcs12", "BB", None, True)

        data, method = libadobeImportAccount.collect_activation_values([adobe, bytebooks])
        self.assertEqual(data, {"credentials": {"pkcs12": {False: "ADOBE", True: "BB"}}},
                         "Unflagged entry followed by ByteBooks entry imported incorrectly")

        data, method = libadobeImportAccount.collect_activation_values([bytebooks, adobe])
        self.assertEqual(data, {"credentials": {"pkcs12": {False: "ADOBE", True: "BB"}}},
                         "ByteBooks entry followed by unflagged entry imported incorrectly")

        # Keys that never have a flag must stay plain values
        data, method = libadobeImportAccount.collect_activation_values([("credentials", "user", "urn:uuid:1234", None, None)])
        self.assertEqual(data, {"credentials": {"user": "urn:uuid:1234"}},
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

            # user.reg is read once, and not at all if the caller passes in what it has read
            registry_reads = []
            def counting_open(path, *args, **kwargs):
                if os.path.basename(path) == "user.reg":
                    registry_reads.append(path)
                return open(path, *args, **kwargs)

            with patch("acsm_input.getEncryptionKeyLinux.GetMasterKey", return_value=bytes(bytearray([0x02] * 16))):
                with patch.object(libadobeImportAccount, "open", counting_open, create=True):
                    success, msg = libadobeImportAccount.importADEactivationLinuxWine(wine_prefix)
                    self.assertTrue(success, "Wine import failed: %s" % (msg))
                    self.assertEqual(len(registry_reads), 1, "user.reg was read %d times" % (len(registry_reads)))

                    activations = libadobeImportAccount.read_wine_activations(wine_prefix)
                    del registry_reads[:]
                    success, msg = libadobeImportAccount.importADEactivationLinuxWine(wine_prefix, activations=activations)
                    self.assertEqual(registry_reads, [], "user.reg was read although the activations were passed in")

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

    def test_readWineActivations(self):
        '''Check if a single pass over user.reg reads both the Adobe and the ByteBooks activation'''

        import tempfile, shutil

        reg = "WINE REGISTRY Version 2\n"
        for vendor in ("Adobe", "ByteBooks"):
            prefix = "Software\\\\%s\\\\Adept\\\\Activation\\\\" % (vendor)
            reg += "\n[%s0001] 1700000000\n@=\"credentials\"\n" % (prefix)
            reg += "\n[%s0001\\\\0000] 1700000000\n@=\"user\"\n\"value\"=\"urn:uuid:%s\"\n" % (prefix, vendor)
            reg += "\n[%s0001\\\\0001] 1700000000\n@=\"username\"\n\"method\"=\"%sID\"\n\"value\"=\"user@%s.example\"\n" % (prefix, vendor, vendor)
        reg += "\n[Software\\\\Wine] 1700000000\n@=\"unrelated\"\n\"value\"=\"ignored\"\n\n"

        temp_dir = tempfile.mkdtemp()
        try:
            f = open(os.path.join(temp_dir, "user.reg"), "w")
            f.write(reg)
            f.close()

            activations = libadobeImportAccount.read_wine_activations(temp_dir)
            for is_bytebooks, vendor in ((False, "Adobe"), (True, "ByteBooks")):
                self.assertEqual(activations[is_bytebooks], [
                    ("credentials", "user", "urn:uuid:" + vendor, None, None),
                    ("credentials", "username", "user@%s.example" % (vendor), vendor + "ID", None),
                ], "%s activation read incorrectly" % (vendor))

            # A registry without an activation has nothing for either vendor
            f = open(os.path.join(temp_dir, "user.reg"), "w")
            f.write("WINE REGISTRY Version 2\n\n[Software\\\\Wine] 1700000000\n@=\"unrelated\"\n\n")
            f.close()
            self.assertEqual(libadobeImportAccount.read_wine_activations(temp_dir), {False: None, True: None})

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


    def test_importWrongEncryptionKey(self):
        '''Check if the import fails if the encryption key doesn't decrypt the private license key'''

        # The padding used to be removed without checking it, so with the wrong key (for instance
        # the one of the other vendor) the import stored garbage as the key and reported success.

        fingerprint = base64.b64encode(bytes(bytearray([0x01] * 20))).decode("ascii")
        values = [
            ("credentials", "privateLicenseKey", encrypt_license_key(bytes(bytearray(32)), bytes(bytearray([0x02] * 16)), fingerprint), None, None),
            ("activationToken", "fingerprint", fingerprint, None, None),
        ]
        success, msg = libadobeImportAccount.import_registry_activation(values, bytes(bytearray([0x03] * 16)), libadobeImportAccount.VAR_VER_DEFAULT_BUILD_ID)
        self.assertFalse(success, "Import with the wrong encryption key should fail")
        self.assertIn("Could not decrypt the private license key", msg)

    def test_importWindowsRegistry(self):
        '''Check if the Windows import reads the activation from the registry'''

        # A ByteBooks activation, with ByteBooks and Adobe variants of some values and a username
        user = "urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa"
        activation = [
            ("activationServiceInfo", [
                ("authURL", "https://auth.example.com/adept", None, None),
                ("userInfoURL", "https://userinfo.example.com/adept", None, None),
                ("activationURL", "https://activate.example.com/adept", None, None),
                ("certificate", "ASI_CERT_BB", None, "true"),
                ("certificate", "ASI_CERT_ADOBE", None, None),
                ("authenticationCertificate", "ASI_AUTH", None, None),
            ]),
            ("credentials", [
                ("user", user, None, None),
                ("username", "user@example.com", "AdobeID", None),
                ("pkcs12", "P12_ADOBE", None, "false"),
                ("pkcs12", "P12_BB", None, "true"),
                ("licenseCertificate", "LIC", None, None),
                ("privateLicenseKey", encrypt_license_key(bytes(bytearray(32)), DEVICE_KEYS[True], FINGERPRINT), None, None),
                ("authenticationCertificate", "AUTH", None, None),
            ]),
            ("activationToken", [
                ("device", "urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84", None, None),
                ("fingerprint", FINGERPRINT, None, None),
                ("deviceType", "standalone", None, None),
                ("activationURL", "https://activate.example.com/adept", None, None),
                ("user", user, None, None),
                ("signature", "SIGNATURE", None, None),
            ]),
        ]

        success, msg, key_requests, activationxml = import_from_windows_registry({True: activation})
        self.assertTrue(success, "Windows import failed: %s" % (msg))
        self.assertEqual(key_requests, [True], "Wrong device key requested for a ByteBooks activation")

        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        asi = "./%s/" % (adNS("activationServiceInfo"))
        cred = "./%s/" % (adNS("credentials"))

        def entries(path):
            return sorted((e.get("ofByteBooks"), e.text) for e in activationxml.findall(path))

        self.assertEqual(entries(asi + adNS("certificate")), [("false", "ASI_CERT_ADOBE"), ("true", "ASI_CERT_BB")], "certificate imported incorrectly")
        self.assertEqual(entries(cred + adNS("pkcs12")), [("false", "P12_ADOBE"), ("true", "P12_BB")], "pkcs12 imported incorrectly")
        username = activationxml.find(cred + adNS("username"))
        self.assertEqual((username.text, username.get("method")), ("user@example.com", "AdobeID"), "username imported incorrectly")
        self.assertEqual(activationxml.find(cred + adNS("privateLicenseKey")).text, base64.b64encode(bytes(bytearray(32))).decode("ascii"),
                         "privateLicenseKey decrypted incorrectly")

    def test_importWindowsRegistryPicksCompleteActivation(self):
        '''Check if the Windows import falls back to the Adobe activation if the ByteBooks one is incomplete'''

        # The import used to pick the ByteBooks activation as soon as it had the key Activation\0000,
        # so a partially erased BDE activation next to a working ADE one ended in a KeyError.
        adobe, bytebooks = complete_activation(False), complete_activation(True)
        # (case, activations, keys without a name, expected use_bytebooks argument for GetMasterKey)
        cases = [
            ("ADE and BDE", {False: adobe, True: bytebooks}, (), True),
            ("ADE and BDE without its activation token", {False: adobe, True: bytebooks[:2]}, (), False),
            ("ADE and a single BDE key", {False: adobe, True: [None, None, bytebooks[2]]}, (), False),
            ("ADE and BDE with an activation token without a name", {False: adobe, True: bytebooks},
             ("ByteBooks\\Adept\\Activation\\0002",), False),
        ]
        for label, trees, unnamed_keys, expected in cases:
            success, msg, key_requests, activationxml = import_from_windows_registry(trees, unnamed_keys)
            self.assertTrue(success, "Windows import failed for %s: %s" % (label, msg))
            self.assertEqual(key_requests, [expected], "Wrong activation imported for %s" % (label))

    def test_importWindowsRegistryErrors(self):
        '''Check if the Windows import reports a broken activation instead of raising'''

        # Keys without a name and values the import can't use raised right through to Calibre.
        try:
            # Python 2: print() writes byte strings there, which io.StringIO doesn't accept.
            from StringIO import StringIO  # type: ignore
        except ImportError:
            from io import StringIO

        adobe = complete_activation(False)
        short_fingerprint = adobe[:2] + [("activationToken", [(name, "AAAA" if name == "fingerprint" else value, method, flag)
                                                              for name, value, method, flag in adobe[2][1]])]
        # (case, activations, keys without a name, expected use_bytebooks arguments for GetMasterKey, message)
        cases = [
            ("no activation", {}, (), [], "Could not locate an ADE or BDE activation"),
            ("an ADE value without a name", {False: adobe}, ("Adobe\\Adept\\Activation\\0001\\0002",), [],
             "The ADE activation is incomplete, it lacks credentials/licenseCertificate"),
            ("a fingerprint that's too short", {False: short_fingerprint}, (), [False],
             "There has been an error while reading through the Registry."),
        ]
        for label, trees, unnamed_keys, expected_keys, message in cases:
            # The import prints the traceback of the error, keep that out of the test output.
            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = StringIO(), StringIO()
            try:
                success, msg, key_requests, activationxml = import_from_windows_registry(trees, unnamed_keys)
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr
            self.assertFalse(success, "Windows import worked for %s" % (label))
            self.assertEqual(msg, message, "Wrong message for %s" % (label))
            self.assertEqual(key_requests, expected_keys, "Wrong device key requested for %s" % (label))

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
            # GetMasterKey passes files for the helper's output, so write into those
            def __init__(self, stdout, returncode, popen_args):
                popen_args["stdout"].write(stdout)
                popen_args["stderr"].write(b"Using the Adobe device key\n")
                self.returncode = returncode
            def poll(self):
                return self.returncode

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
                    with patch("subprocess.Popen", side_effect=lambda cmd, **popen_args: MockProcess(stdout, returncode, popen_args)):
                        master_key = getEncryptionKeyLinux.GetMasterKey(wine_prefix)
                finally:
                    sys.stdout, sys.stderr = old_stdout, old_stderr
                self.assertEqual(master_key, expected, "Wrong result for %s" % (label))
        finally:
            shutil.rmtree(wine_prefix)

    def test_wineHelperFailuresAreHandled(self):
        '''Check if GetMasterKey returns None if WINE can't be started or the helper hangs'''

        # A missing wine binary (as in a Flatpak) made Popen raise, so the import showed a
        # traceback instead of an error message, and a WINE that hung froze Calibre's GUI.

        import tempfile, shutil, errno
        from acsm_input import getEncryptionKeyLinux      # type: ignore

        try:
            # Python 2: print() writes byte strings there, which io.StringIO doesn't accept.
            from StringIO import StringIO  # type: ignore
        except ImportError:
            from io import StringIO

        class HangingProcess(object):
            def __init__(self):
                self.returncode = None
                self.killed = False
            def poll(self):
                return self.returncode
            def kill(self):
                self.killed = True
                self.returncode = -9
            def wait(self):
                return self.returncode

        hanging = HangingProcess()
        cases = [
            ("no wine binary", patch("subprocess.Popen", side_effect=OSError(errno.ENOENT, "No such file or directory"))),
            ("an unexpected error", patch("subprocess.Popen", side_effect=RuntimeError("Something went wrong"))),
            ("a helper that hangs", patch("subprocess.Popen", return_value=hanging)),
        ]

        wine_prefix = tempfile.mkdtemp()
        try:
            for label, popen in cases:
                # GetMasterKey logs every step, keep that out of the test output.
                old_stdout, old_stderr = sys.stdout, sys.stderr
                sys.stdout, sys.stderr = StringIO(), StringIO()
                try:
                    with popen, patch.object(getEncryptionKeyLinux, "WINE_TIMEOUT", 0.3):
                        master_key = getEncryptionKeyLinux.GetMasterKey(wine_prefix)
                finally:
                    sys.stdout, sys.stderr = old_stdout, old_stderr
                self.assertIsNone(master_key, "Wrong result for %s" % (label))
            self.assertTrue(hanging.killed, "The helper that hangs wasn't killed")
        finally:
            shutil.rmtree(wine_prefix)

    def test_importWineKeySourceMatchesActivation(self):
        '''Check if the Wine key helper is asked for the device key of the imported activation'''

        import tempfile, shutil

        try:
            from unittest.mock import call
        except ImportError:
            from mock import call

        # The ByteBooks activation is imported if it's complete, otherwise the Adobe one. The import
        # used to pick the ByteBooks one as soon as it had any key, so a partially erased BDE
        # activation, or a key that BDE left behind, broke the import of a working ADE activation.
        adobe, bytebooks = complete_activation(False), complete_activation(True)
        # (case, activations in user.reg, expected use_bytebooks argument for GetMasterKey,
        # or None if the import has to fail before it asks for a key)
        cases = [
            ("ADE", {False: adobe}, False),
            ("BDE", {True: bytebooks}, True),
            ("ADE and BDE", {False: adobe, True: bytebooks}, True),
            ("ADE and BDE without its activation token", {False: adobe, True: bytebooks[:2]}, False),
            ("ADE and a single BDE key", {False: adobe, True: [None, None, bytebooks[2]]}, False),
            ("only BDE without its activation token", {True: bytebooks[:2]}, None),
        ]

        for label, trees, expected in cases:
            temp_dir = tempfile.mkdtemp()
            try:
                f = open(os.path.join(temp_dir, "user.reg"), "w")
                f.write(wine_registry(trees))
                f.close()

                # Without a key the import stops right after asking for it, which is all this test needs.
                with patch("acsm_input.getEncryptionKeyLinux.GetMasterKey", return_value=None) as get_master_key:
                    success, msg = libadobeImportAccount.importADEactivationLinuxWine(temp_dir)

                self.assertFalse(success, "Import without a device key should fail for %s" % (label))
                if expected is None:
                    self.assertEqual(get_master_key.call_args_list, [], "Device key requested for %s" % (label))
                    self.assertIn("The BDE activation is incomplete", msg)
                else:
                    self.assertEqual(get_master_key.call_args_list, [call(temp_dir, expected)],
                                     "Wrong device key requested for %s" % (label))
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

