#!/usr/bin/python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see:
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, os
sys.path.append("../calibre-plugin")


import unittest
import base64
import binascii
import shutil
import tempfile
if sys.version_info[0] >= 3:
    from unittest.mock import patch
    from io import StringIO
else:
    from mock import patch
    from StringIO import StringIO
from lxml import etree

from acsm_input import libadobe             # type: ignore
from acsm_input import libadobeFulfill      # type: ignore


# A test account with the credentials of both vendors. Each vendor's pkcs12 has a key of its
# own, so a signature shows which one signed a request. The password is the device key in
# base64, like in a real activation. Made with OpenSSL (and the same for Adobe):
#   openssl genrsa -traditional -out ByteBooks.key 1024
#   openssl req -new -x509 -key ByteBooks.key -subj "/CN=ACSM Input unit tests (ByteBooks)" -days 36500 -sha256 -out ByteBooks.crt
#   openssl pkcs12 -export -inkey ByteBooks.key -in ByteBooks.crt -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -passout pass:QUNTTSBJbnB1dCB0ZXN0cw== -out ByteBooks.p12

DEVICE_KEY = b"ACSM Input tests"

PKCS12 = {
    "ByteBooks": "MIIGMQIBAzCCBfcGCSqGSIb3DQEHAaCCBegEggXkMIIF4DCCAt8GCSqGSIb3DQEHBqCCAtAwggLMAgEAMIICxQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQI2NLdtak8BloCAggAgIICmO+8Hn/XWZ5joGKYbF8Ghxn6TpjlaM66earXFFLOuMYcSWSL5FvKOywjP65FDHp/YSxqg0xcpM+6gN4R7pHGc5oapCDZIY7LM3U/Q2TS+jzj9xPvodWCTmpLf/BSL9/9A/QXX0Q95U8DpB0NqRlmGmNDYNTWyCBsJ40Lqgh5rRpddQSSMzkkW0MAmZ0+/UW74jf9DL0rw4QCr+BsTSY+wLia+z5HVL7oomriccIDZQkYu5ov/q1C8C7BQha06iXB2hJ31EcdrynTxAWiy1ln+yfCfvHz0imlXf9a/YL8d+Z5Qg0QMoxBUYMkdICQzZLff4MaSIZolvaa65wL/fTFNJ7rl1nzf2NBB8C6yyDL4N3Kq/pu/WKDj7cLjxzEPDktuN1oQybiyoQ7ie3ZniRmoOdSZsqF0HN0DToPAE/tQQxezhmncjGVr9MBB5ZwFQbrMM4CX8xZzcV8CaYsvDKtd8KTVKo9IxrBELhOGuYiqB6J2bMU+/P5yUDYagabJIm9SlNFN/EcBVOh3Njhd+hatynXRsYzJ1NKMVWS0rcJyQOqUnpkjQQX2hc/fvSE8PqhVgVgWH/9j6oJeO3ao0Gwi0IPqpW5+VBD/B5QOQc12lkYQoDiNJaNmfrCkN8/7NiuHd/J1AFaUIZek327fPhXYOimJvOWX4qr8QuiBctX1r1SipQZLtWlzXl1VOLlBr0JQhfYyXvfZ+dnX4g7XOvZBXsAoRXVqjnlB6m0taBXVopX/6ectctwPOmTSvJV00Yk2G02mHbs1gI9bCBi4Hbd8/NOI2/SGnmkOELetTR5S71bELD2ksdVaHuSe2EYthnVhr8A7ZwxeEhdAsMSrDFeN3BeG+sbX6X+XJ+ZQ078kUkhMglsFy6LvWwwggL5BgkqhkiG9w0BBwGgggLqBIIC5jCCAuIwggLeBgsqhkiG9w0BDAoBAqCCAqYwggKiMBwGCiqGSIb3DQEMAQMwDgQIoXptle8QmgMCAggABIICgMsbYLLjZ0EoqESOVtiybb8LUFsQNFGsYf14SAyHi7rg9z2vBTz80HxFNrM262MdJqYTVw3/ZvFuA6Hv8ni91Ea1A8lP5pm6GoumuVZtXOj8umn+ImV68BW4pRfj7cyvX03mC8080Sy+T0m/oRSKdgZE6uNgFCFESgDG6Vd/we6bn3AiNmiyJJAp66Cv/hxM0t0vhh0odiREfjLaEvPoBzPrxO6F33q77BqiibRn5R6lIcd1nAwjcYp+wssNXTZqFcgIMOuS0Iloa8HbA7mfxi/1XZh8bIlq4/re7DNHYWv7vg2JUC8M2evs6/G/bIl7J4FtphiurexBQdmnNTLTs20NC+lDuq/kMbp4llAizlFdjrhUfGjA7pj9jwKSOHrb8IFCUx+xkYwQb3q8DtB2/Q7LlYmaF6Ras/guqx4Mwdece/9VMYNUNX7Mp/mVfA3KGOtTRu7xJqE7MU1xRYbb+Txl5X6j2HdxMOr0/Y66lLgp5LsnxIrupzxoWWZDEzLrDHHv5DA6netwwmDNIeFetyqHjungdjPAzYTEHyzzf4u/JeOWuzH1OALnEUyUHtIbcN/MJBxrKqzQwTXSJtsGStCwRkgRApba3mmi3qcKDHcsECeSEH6jEtQq4B8mEHhdI+oDHXRswzpXlmJw3G5xPzOZLCVjVDAnHBi8vHZzRmikhGP5KX8nZznkBo/VcoHVMrxjoYx6wfsaw4zuWpWss6C0qq1esgm+TPvs7vbdTRwc2urb+d+hZQ8/vfzg+XFaDmXDiQ4YP/er7AC7pdtt90LWNsi4/GMeqC/73jn28M5WO+wjKkxN8dAHHTRWfbp2TI3erzKdNW4Qq9LU21eWEs4xJTAjBgkqhkiG9w0BCRUxFgQUXKgafg+AKeieQ31mGMaddafVSUYwMTAhMAkGBSsOAwIaBQAEFIAUusQahAfN4lhz3lWaxMdaWoHQBAi0BfRrxekjLQICCAA=",
    "Adobe": "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",
}

# The certificates in the pkcs12 files (openssl x509 -outform DER), and the moduli of their
# public keys (openssl x509 -noout -modulus). The public exponent is 65537.
CERTIFICATES = {
    "ByteBooks": "MIICNjCCAZ+gAwIBAgIUf/S8MyZ0XCdFC1Cv79iswSiiiEEwDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UEAwwhQUNTTSBJbnB1dCB1bml0IHRlc3RzIChCeXRlQm9va3MpMCAXDTI2MTEyNjA3NTYyMFoYDzIxMjYxMTAyMDc1NjIwWjAsMSowKAYDVQQDDCFBQ1NNIElucHV0IHVuaXQgdGVzdHMgKEJ5dGVCb29rcykwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAND6twOwx8UjXdvq+Na6Y5m2ticn28G+paHlbt0EchaO/6oEhlGERMaEls1cYaYHPz6GQqdbiZGdamMH8XokH3hwCKbcZ0afUxxxukufzysM7MGFkjRihGWIu0bYvzwE0hWtC5i0cCWV0HuX7Ohv58jck/+KPT6mUM4hrgBMrejBAgMBAAGjUzBRMB0GA1UdDgQWBBRTifM6ZIcZP2JxmqY09WuzLgcljDAfBgNVHSMEGDAWgBRTifM6ZIcZP2JxmqY09WuzLgcljDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBABakLNGvxLSf2Wbwsg3Ewm0I/gEhYZy2yY5mqRQWhPZ4pcXdrKsc1SbkYL2HVbc4vPOWY94ec0ujWkvxWZXysX9cSnRuBFItuHQJn9oAaA0WNG8uhCkhabjE1GmyoI6gitI/5pJ6fRvr/7VJj2Oo9R+xjS1/GsJQ75lRMYmSwPex",
    "Adobe": "MIICLjCCAZegAwIBAgIUVILsI2oBOgvd7fd+Z6hvV4PkrZAwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAwwdQUNTTSBJbnB1dCB1bml0IHRlc3RzIChBZG9iZSkwIBcNMjYxMTI2MDc1NjIwWhgPMjEyNjExMDIwNzU2MjBaMCgxJjAkBgNVBAMMHUFDU00gSW5wdXQgdW5pdCB0ZXN0cyAoQWRvYmUpMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDpI533fdE2kqIb+QopVMy/Eqh8YI+FOx9J1qevy/54NjEhKIWExv4jT2q4l2MO5xG05cNZpqip4nrMpqSuAqeO1xLcEJqi2RYGd0JOJsiemrUn22hbo0c+aRrOp45FsQaSHxCkjfaPOY5o/PechGf4R4SQSREQXQs+NCA8G/75hQIDAQABo1MwUTAdBgNVHQ4EFgQUHn4EZZyRk896AN2KPSUHUigO75cwHwYDVR0jBBgwFoAUHn4EZZyRk896AN2KPSUHUigO75cwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCSHHIU6XvNJGIWVMj5uDaquCBHknPoENQ6Mvng5bDV7TT3+M7+LTrsbVjcpSb+TCk0KNhwXMmHKAHPQbz4Nup1nvvh4WEKQooyMu4ZysMyhcJAAe0yMSo+Y6F43eElrSNcf/DhoQjYLEEf/3apMt7bS7XV4t65LmXwF0HYnTkETQ==",
}

MODULI = {
    "ByteBooks": 0xd0fab703b0c7c5235ddbeaf8d6ba6399b6b62727dbc1bea5a1e56edd0472168effaa0486518444c68496cd5c61a6073f3e8642a75b89919d6a6307f17a241f787008a6dc67469f531c71ba4b9fcf2b0cecc185923462846588bb46d8bf3c04d215ad0b98b4702595d07b97ece86fe7c8dc93ff8a3d3ea650ce21ae004cade8c1,
    "Adobe": 0xe9239df77dd13692a21bf90a2954ccbf12a87c608f853b1f49d6a7afcbfe78363121288584c6fe234f6ab897630ee711b4e5c359a6a8a9e27acca6a4ae02a78ed712dc109aa2d9160677424e26c89e9ab527db685ba3473e691acea78e45b106921f10a48df68f398e68fcf79c8467f84784904911105d0b3e34203c1bfef985,
}

USER = "urn:uuid:11111111-2222-3333-4444-555555555555"
DEVICE = "urn:uuid:66666666-7777-8888-9999-000000000000"
OPERATOR = "https://acs.example.invalid/fulfillment"
ACTIVATION_URL = "https://activation.example.invalid/adept"
LICENSE_URL = "https://license.example.invalid/licensesign"
NOTIFY_URL = "https://notify.example.invalid/notify"

ADEPT = "{http://ns.adobe.com/adept}"


def activation_xml(bytebooks=True, adobe=True, adobe_flag=True, operators=()):
    '''An activation.xml for the test account, with the credentials of these vendors. Without
    adobe_flag, the Adobe credentials have no ofByteBooks flag, like in activations from ADE
    and older plugin versions. operators are the operator URLs it's authenticated to.'''

    credentials = ""
    for vendor, present, flag in (("ByteBooks", bytebooks, ' ofByteBooks="true"'),
                                  ("Adobe", adobe, ' ofByteBooks="false"' if adobe_flag else "")):
        if present:
            credentials += '<adept:pkcs12%s>%s</adept:pkcs12>' % (flag, PKCS12[vendor])
            credentials += '<adept:licenseCertificate%s>%s license certificate</adept:licenseCertificate>' % (flag, vendor)
            credentials += '<adept:authenticationCertificate%s>%s authentication certificate</adept:authenticationCertificate>' % (flag, vendor)

    operator_list = ""
    if operators:
        operator_list = '<adept:operatorURLList><adept:user>%s</adept:user>%s</adept:operatorURLList>' % (
            USER, "".join('<adept:operatorURL>%s</adept:operatorURL>' % (url) for url in operators))

    return ('<?xml version="1.0"?>\n'
            '<activationInfo xmlns="http://ns.adobe.com/adept" xmlns:adept="http://ns.adobe.com/adept">'
            '<adept:credentials><adept:user>%s</adept:user>%s</adept:credentials>'
            '<adept:activationToken><adept:device>%s</adept:device><adept:fingerprint>ZmluZ2VycHJpbnQ=</adept:fingerprint>'
            '<adept:deviceType>standalone</adept:deviceType><adept:activationURL>%s</adept:activationURL>'
            '<adept:user>%s</adept:user></adept:activationToken>%s</activationInfo>') % (
            USER, credentials, DEVICE, ACTIVATION_URL, USER, operator_list)


DEVICE_XML = '''<?xml version="1.0"?>
<adept:deviceInfo xmlns:adept="http://ns.adobe.com/adept">
<adept:deviceType>standalone</adept:deviceType>
<adept:fingerprint>ZmluZ2VycHJpbnQ=</adept:fingerprint>
<adept:version name="hobbes" value="12.5.4.HOBBES_VERSION_BUILD_NUMBER_X"/>
<adept:version name="clientOS" value="Windows 10"/>
<adept:version name="clientLocale" value="en"/>
</adept:deviceInfo>
'''

ACSM = '''<?xml version="1.0"?>
<fulfillmentToken fulfillmentType="buy" auth="user" xmlns="http://ns.adobe.com/adept">
<distributor>urn:uuid:00000000-0000-0000-0000-000000000001</distributor>
<operatorURL>%s</operatorURL>
<transaction>TRANSACTION-1</transaction>
<expiration>2099-01-01T00:00:00+00:00</expiration>
<resourceItemInfo>
<resource>urn:uuid:00000000-0000-0000-0000-000000000002</resource>
<resourceItem>0</resourceItem>
<metadata>
<dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Test book</dc:title>
<dc:format xmlns:dc="http://purl.org/dc/elements/1.1/">application/epub+zip</dc:format>
</metadata>
</resourceItemInfo>
<hmac>AAAA</hmac>
</fulfillmentToken>
''' % (OPERATOR)


def fulfillment_reply(notify=""):
    '''The operator's reply to a fulfill request'''
    return ('<envelope xmlns="http://ns.adobe.com/adept"><fulfillmentResult>'
            '<fulfillment>FULFILLMENT-1</fulfillment><returnable>false</returnable><initial>true</initial>'
            '<resourceItemInfo><resource>urn:uuid:00000000-0000-0000-0000-000000000002</resource>'
            '<licenseToken><user>%s</user><device>%s</device><licenseURL>%s</licenseURL></licenseToken>'
            '</resourceItemInfo>%s</fulfillmentResult></envelope>') % (USER, DEVICE, LICENSE_URL, notify)

# A critical and an optional notification
NOTIFY = ('<notify><notifyURL>%s</notifyURL><body><fulfillment>FULFILLMENT-1</fulfillment></body></notify>'
          '<notify critical="no"><notifyURL>%s?id=2</notifyURL><body><fulfillment>FULFILLMENT-1</fulfillment></body></notify>') % (NOTIFY_URL, NOTIFY_URL)

LOAN_RETURN_REPLY = ('<envelope xmlns="http://ns.adobe.com/adept"><loanReturnResult/>'
                     '<notify><notifyURL>%s</notifyURL><body><loan>LOAN-1</loan></body></notify></envelope>') % (NOTIFY_URL)

SUCCESS = '<success xmlns="http://ns.adobe.com/adept"/>'
ERROR = '<error xmlns="http://ns.adobe.com/adept" data="E_TEST_ERROR"/>'
INVALID_CERTIFICATE = '<error xmlns="http://ns.adobe.com/adept" data="E_ADEPT_INVALID_CERTIFICATE %s/Auth"/>' % (OPERATOR)


# (credentials in the activation, prefer_bytebooks, whose credentials have to be used)
VENDOR_CASES = [
    ({}, True, "ByteBooks"),
    ({}, False, "Adobe"),
    # The other vendor's, if the preferred one has none
    ({"adobe": False}, False, "ByteBooks"),
    ({"bytebooks": False}, True, "Adobe"),
    # Activations from ADE and older plugin versions have no ofByteBooks flags, that's Adobe
    ({"bytebooks": False, "adobe_flag": False}, True, "Adobe"),
]


class FakeServer(object):
    '''Stands in for send_adept. It records the requests and answers each one with the next
    reply: a string, (HTTP status, string), or an exception to raise.'''

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []      # (URL, request XML)

    def send(self, url, document, validate_tls, allow_no_content=False):
        if not isinstance(document, bytes):
            document = document.encode("utf-8")
        self.requests.append((url, etree.fromstring(document)))

        reply = self.replies.pop(0) if self.replies else '<error xmlns="http://ns.adobe.com/adept" data="E_TEST_UNEXPECTED_REQUEST"/>'
        if isinstance(reply, Exception):
            raise reply
        status, body = reply if isinstance(reply, tuple) else (200, reply)
        if status == 204 and allow_no_content:
            return None
        return etree.fromstring(body.encode("utf-8"))


def quietly(function, *args):
    '''Calls function(*args) without its output, the plugin logs a lot while talking to servers'''
    with patch.object(sys, "stdout", StringIO()), patch.object(sys, "stderr", StringIO()):
        return function(*args)


class TestAdobeRequests(unittest.TestCase):

    def setUp(self):
        self.account_dir = tempfile.mkdtemp()
        self.write_file("devicesalt", DEVICE_KEY)
        self.write_file("device.xml", DEVICE_XML)
        self.write_file("activation.xml", activation_xml())
        libadobe.update_account_path(self.account_dir)

    def tearDown(self):
        libadobe.update_account_path("")
        shutil.rmtree(self.account_dir, ignore_errors=True)

    def write_file(self, name, data):
        '''Writes a file to the test account folder, or deletes it if data is None'''
        path = os.path.join(self.account_dir, name)
        if data is None:
            if os.path.exists(path):
                os.remove(path)
            return
        if not isinstance(data, bytes):
            data = data.encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)

    def write_activation(self, **credentials):
        self.write_file("activation.xml", activation_xml(**credentials))

    def signer(self, node, signature):
        '''Whose key made this signature for the node: "ByteBooks", "Adobe" or None. Like the
        server checks it: with the public key, the signature has to turn back into the hash
        of the node, with PKCS#1 v1.5 padding.'''

        if signature is None:
            return None
        signature = int(binascii.hexlify(base64.b64decode(signature)), 16)
        digest = libadobe.hash_node(node).digest()      # leaves out the signature element

        for vendor, modulus in MODULI.items():
            size = (modulus.bit_length() + 7) // 8
            padded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
            if pow(signature, 65537, modulus) == int(binascii.hexlify(padded), 16):
                return vendor
        return None

    def vendor_of(self, request):
        '''Whose credentials a request uses: the signature, or for an /Auth request, the certificates'''
        signature = request.find(ADEPT + "signature")
        if signature is not None:
            return self.signer(request, signature.text)
        for vendor in ("ByteBooks", "Adobe"):
            if [request.findtext(ADEPT + tag) for tag in ("certificate", "licenseCertificate", "authenticationCertificate")] == \
                    [CERTIFICATES[vendor], vendor + " license certificate", vendor + " authentication certificate"]:
                return vendor
        return None

    def sent(self, server):
        '''The requests that reached the server, as (URL, whose credentials they use)'''
        return [(url, self.vendor_of(request)) for url, request in server.requests]


    def test_signNode(self):
        '''Check if sign_node signs with the key of the preferred vendor'''

        node = etree.fromstring('<adept:test xmlns:adept="http://ns.adobe.com/adept"><adept:user>%s</adept:user></adept:test>' % (USER))

        for credentials, prefer_bytebooks, expected in VENDOR_CASES:
            self.write_activation(**credentials)
            signature = libadobe.sign_node(node, prefer_bytebooks)
            self.assertEqual(self.signer(node, signature), expected,
                             "Wrong signature for %r, prefer_bytebooks=%s" % (credentials, prefer_bytebooks))


    def test_signNodeFailures(self):
        '''Check if sign_node returns None if it can't sign'''

        node = etree.fromstring('<adept:test xmlns:adept="http://ns.adobe.com/adept"/>')

        # (what's wrong, activation.xml, devicesalt), None for a missing file
        cases = [
            ("no pkcs12", activation_xml(bytebooks=False, adobe=False), DEVICE_KEY),
            ("a corrupt pkcs12", activation_xml(adobe=False).replace(PKCS12["ByteBooks"], "bm90IGEgcGtjczEy"), DEVICE_KEY),
            ("a device key that doesn't decrypt the pkcs12", activation_xml(), b"Some other key!!"),
            ("no devicesalt", activation_xml(), None),
            ("no activation.xml", None, DEVICE_KEY),
        ]

        for problem, activation, device_key in cases:
            self.write_file("activation.xml", activation)
            self.write_file("devicesalt", device_key)
            libadobe.update_account_path(self.account_dir)      # forget the device key of the last case
            self.assertIsNone(quietly(libadobe.sign_node, node, True), "Signed with %s" % (problem))

        # A node that can't be hashed, with a valid account
        self.write_file("activation.xml", activation_xml())
        self.write_file("devicesalt", DEVICE_KEY)
        libadobe.update_account_path(self.account_dir)
        node = etree.fromstring('<!DOCTYPE test [<!ENTITY e "x">]><adept:test xmlns:adept="http://ns.adobe.com/adept">&e;</adept:test>',
                                parser=libadobe.safe_xml_parser())
        self.assertIsNone(quietly(libadobe.sign_node, node, True), "Signed a node with an entity reference")


    def test_getDecryptedCert(self):
        '''Check if getDecryptedCert returns the certificate of the preferred vendor'''

        for credentials, prefer_bytebooks, expected in VENDOR_CASES:
            self.write_activation(**credentials)
            self.assertEqual(libadobeFulfill.getDecryptedCert(None, prefer_bytebooks), base64.b64decode(CERTIFICATES[expected]),
                             "Wrong certificate for %r, prefer_bytebooks=%s" % (credentials, prefer_bytebooks))

        self.assertEqual(libadobeFulfill.getDecryptedCert(PKCS12["Adobe"], True), base64.b64decode(CERTIFICATES["Adobe"]),
                         "Wrong certificate for a pkcs12 that's passed in")

        self.write_activation(bytebooks=False, adobe=False)
        self.assertIsNone(libadobeFulfill.getDecryptedCert(None, True), "Returned a certificate without a pkcs12")


    def operator_auth(self, *replies):
        '''Runs doOperatorAuth with a server that gives these replies, returns its result and the server'''
        server = FakeServer(*replies)
        with patch.object(libadobeFulfill, "send_adept", server.send):
            result = quietly(libadobeFulfill.doOperatorAuth, OPERATOR + "/Fulfill")
        return result, server

    AUTH_BYTEBOOKS = (OPERATOR + "/Auth?ofByteBooks=1", "ByteBooks")
    AUTH_ADOBE = (OPERATOR + "/Auth", "Adobe")
    INIT_BYTEBOOKS = (ACTIVATION_URL + "/InitLicenseService?ofByteBooks=1", "ByteBooks")
    INIT_ADOBE = (ACTIVATION_URL + "/InitLicenseService", "Adobe")

    def test_operatorAuth(self):
        '''Check if doOperatorAuth tries the ByteBooks credentials first'''

        # (credentials in the activation, server replies, result, requests)
        cases = [
            ({}, [SUCCESS, SUCCESS], (None, True), [self.AUTH_BYTEBOOKS, self.INIT_BYTEBOOKS]),
            # An operator that doesn't accept the ByteBooks certificates
            ({}, [INVALID_CERTIFICATE, SUCCESS, SUCCESS], (None, False), [self.AUTH_BYTEBOOKS, self.AUTH_ADOBE, self.INIT_ADOBE]),
            ({"bytebooks": False, "adobe_flag": False}, [SUCCESS, SUCCESS], (None, False), [self.AUTH_ADOBE, self.INIT_ADOBE]),
        ]

        for credentials, replies, expected_result, expected_requests in cases:
            self.write_activation(**credentials)
            result, server = self.operator_auth(*replies)

            self.assertEqual(result, expected_result, "Wrong result for %r, %r" % (credentials, replies))
            self.assertEqual(self.sent(server), expected_requests, "Wrong requests for %r, %r" % (credentials, replies))
            for url, request in server.requests:
                self.assertEqual(request.findtext(ADEPT + "user"), USER, "Wrong user in the request to %s" % (url))
                if "/InitLicenseService" in url:
                    self.assertEqual(request.findtext(ADEPT + "operatorURL"), OPERATOR, "Wrong operator in the license service request")


    def test_operatorAuthErrors(self):
        '''Check if doOperatorAuth reports errors and falls back to Adobe if rejected'''

        # (credentials in the activation, server replies, requests)
        cases = [
            ({}, [ERROR], [self.AUTH_BYTEBOOKS]),
            ({}, [libadobe.RequestError("Connection refused")], [self.AUTH_BYTEBOOKS]),
            ({}, [SUCCESS, ERROR], [self.AUTH_BYTEBOOKS, self.INIT_BYTEBOOKS]),
            # No Adobe credentials to fall back to
            ({"adobe": False}, [INVALID_CERTIFICATE], [self.AUTH_BYTEBOOKS]),
            # No complete set of credentials at all
            ({"bytebooks": False, "adobe": False}, [], []),
        ]

        for credentials, replies, expected_requests in cases:
            self.write_activation(**credentials)
            (error, use_bytebooks), server = self.operator_auth(*replies)

            self.assertIsNotNone(error, "No error for %r, %r" % (credentials, replies))
            self.assertIsNone(use_bytebooks, "Returned a certificate type for %r, %r" % (credentials, replies))
            self.assertEqual(self.sent(server), expected_requests, "Wrong requests for %r, %r" % (credentials, replies))


    def test_fulfill(self):
        '''Check if fulfill signs with the ByteBooks key and falls back to Adobe if necessary'''

        self.write_file("book.acsm", ACSM)
        fulfill_bytebooks = (OPERATOR + "/Fulfill?ofByteBooks=1", "ByteBooks")
        fulfill_adobe = (OPERATOR + "/Fulfill", "Adobe")

        # (credentials in the activation, server replies, requests,
        #  use_bytebooks for the license download, or None if fulfill fails)
        cases = [
            ({}, [fulfillment_reply()], [fulfill_bytebooks], True),
            # An operator that doesn't accept the ByteBooks certificates
            ({}, [INVALID_CERTIFICATE, fulfillment_reply()], [fulfill_bytebooks, fulfill_adobe], False),
            ({"bytebooks": False, "adobe_flag": False}, [fulfillment_reply()], [fulfill_adobe], False),
            # No Adobe credentials to fall back to
            ({"adobe": False}, [INVALID_CERTIFICATE], [fulfill_bytebooks], None),
        ]

        for credentials, replies, expected_requests, use_bytebooks in cases:
            # Already authenticated to the operator, so fulfill doesn't know which certificate it accepts
            self.write_activation(operators=[OPERATOR + "/Fulfill"], **credentials)
            server = FakeServer(*replies)
            license_downloads = []
            with patch.object(libadobeFulfill, "send_adept", server.send), \
                    patch.object(libadobeFulfill, "fetchLicenseServiceCertificate", lambda *args: license_downloads.append(args) or (True, "")):
                success, reply = quietly(libadobeFulfill.fulfill, os.path.join(self.account_dir, "book.acsm"))

            self.assertEqual(self.sent(server), expected_requests, "Wrong requests for %r, %r" % (credentials, replies))
            if use_bytebooks is None:
                self.assertFalse(success, "No error for %r, %r" % (credentials, replies))
                self.assertEqual(license_downloads, [], "Downloaded a license after an error")
            else:
                self.assertTrue(success, "Fulfillment failed for %r, %r: %s" % (credentials, replies, reply))
                self.assertEqual(license_downloads, [(LICENSE_URL, OPERATOR, use_bytebooks)], "Wrong license download for %r, %r" % (credentials, replies))


    def test_fulfillDoctype(self):
        '''Check if fulfill handles an ACSM with a DOCTYPE, and rejects one with entity references'''

        self.write_activation(operators=[OPERATOR + "/Fulfill"])
        header = '<?xml version="1.0"?>\n'
        assert ACSM.startswith(header)

        # A DOCTYPE without entity references doesn't change anything. It must not end up in the request.
        self.write_file("book.acsm", header + '<!DOCTYPE fulfillmentToken>\n' + ACSM[len(header):])
        server = FakeServer(fulfillment_reply())
        with patch.object(libadobeFulfill, "send_adept", server.send), \
                patch.object(libadobeFulfill, "fetchLicenseServiceCertificate", lambda *args: (True, "")):
            success, reply = quietly(libadobeFulfill.fulfill, os.path.join(self.account_dir, "book.acsm"))
        self.assertTrue(success, "Fulfillment failed for an ACSM with a DOCTYPE: %s" % (reply))
        self.assertEqual(self.sent(server), [(OPERATOR + "/Fulfill?ofByteBooks=1", "ByteBooks")], "Wrong requests for an ACSM with a DOCTYPE")
        self.assertEqual(server.requests[0][1].findtext(ADEPT + "fulfillmentToken/" + ADEPT + "transaction"), "TRANSACTION-1",
                         "The ACSM isn't in the fulfill request")

        # An entity reference is an error, before anything is sent
        acsm = header + '<!DOCTYPE fulfillmentToken [<!ENTITY t "TRANSACTION-1">]>\n' + ACSM[len(header):].replace("TRANSACTION-1", "&t;")
        self.write_file("book.acsm", acsm)
        server = FakeServer(fulfillment_reply())
        with patch.object(libadobeFulfill, "send_adept", server.send):
            success, reply = quietly(libadobeFulfill.fulfill, os.path.join(self.account_dir, "book.acsm"))
        self.assertFalse(success, "No error for an ACSM with an entity reference")
        self.assertIn("entity", reply, "Wrong error for an ACSM with an entity reference")
        self.assertEqual(server.requests, [], "Sent a request for an ACSM with an entity reference")


    def test_fulfillmentNotification(self):
        '''Check if fulfillment notifications are signed with the right key and sent to the right URLs'''

        reply = etree.fromstring(fulfillment_reply(NOTIFY))

        for use_bytebooks, vendor, urls in [
                (True, "ByteBooks", [NOTIFY_URL + "?ofByteBooks=1", NOTIFY_URL + "?id=2&ofByteBooks=1"]),
                (False, "Adobe", [NOTIFY_URL, NOTIFY_URL + "?id=2"])]:
            server = FakeServer(SUCCESS, SUCCESS)
            with patch.object(libadobeFulfill, "send_adept", server.send):
                result = quietly(libadobeFulfill.performFulfillmentNotification, reply, use_bytebooks)

            self.assertEqual(result, (True, ""), "Notification failed, use_bytebooks=%s" % (use_bytebooks))
            self.assertEqual(self.sent(server), [(url, vendor) for url in urls], "Wrong notifications, use_bytebooks=%s" % (use_bytebooks))
            for url, request in server.requests:
                # The user and device from the license token, and the body from the reply
                self.assertEqual([request.findtext(ADEPT + tag) for tag in ("user", "device", "body/" + ADEPT + "fulfillment")],
                                 [USER, DEVICE, "FULFILLMENT-1"], "Wrong notification for %s" % (url))


    def test_fulfillmentNotificationErrors(self):
        '''Check if only failed critical notifications count as errors'''

        reply = etree.fromstring(fulfillment_reply(NOTIFY))

        # (replies to the critical and the optional notification, success)
        cases = [
            ([(204, ""), SUCCESS], True),
            ([SUCCESS, ERROR], True),
            ([SUCCESS, libadobe.RequestError("Connection refused")], True),
            ([ERROR, SUCCESS], False),
            ([(200, "<html>Bad gateway</html>"), SUCCESS], False),
            ([libadobe.RequestError("Connection refused"), SUCCESS], False),
        ]

        for replies, expected in cases:
            server = FakeServer(*replies)
            with patch.object(libadobeFulfill, "send_adept", server.send):
                success, message = quietly(libadobeFulfill.performFulfillmentNotification, reply, True)
            self.assertEqual(success, expected, "Wrong result for %r: %s" % (replies, message))
            self.assertEqual(len(server.requests), 2, "Didn't send both notifications for %r" % (replies,))

        self.assertEqual(quietly(libadobeFulfill.performFulfillmentNotification, etree.fromstring(fulfillment_reply()), True), (True, ""),
                         "Error for a reply without notifications")


    def test_fulfillmentNotificationInvalid(self):
        '''Check if broken notifications from the server are errors, not exceptions'''

        good = '<notify><notifyURL>%s</notifyURL><body><fulfillment>FULFILLMENT-1</fulfillment></body></notify>' % (NOTIFY_URL)
        no_url = '<notify%s><body><fulfillment>FULFILLMENT-1</fulfillment></body></notify>'
        no_body = '<notify%s><notifyURL>' + NOTIFY_URL + '?id=2</notifyURL></notify>'
        # A device ID that doesn't fit into the request
        bad_device = fulfillment_reply(good).replace(DEVICE, "&lt;broken")

        # (fulfillment reply, success, number of requests)
        cases = [
            (fulfillment_reply(no_url % ("") + good), False, 1),
            (fulfillment_reply(no_url % (' critical="no"') + good), True, 1),
            (fulfillment_reply(good + no_body % ("")), False, 1),
            (fulfillment_reply(good + no_body % (' critical="no"')), True, 1),
            (bad_device, False, 0),
        ]

        for reply, expected, request_count in cases:
            server = FakeServer(SUCCESS, SUCCESS)
            with patch.object(libadobeFulfill, "send_adept", server.send):
                success, message = quietly(libadobeFulfill.performFulfillmentNotification, etree.fromstring(reply), True)
            self.assertEqual(success, expected, "Wrong result for %s: %s" % (reply, message))
            self.assertEqual(len(server.requests), request_count, "Wrong number of notifications for %s" % (reply))
            if not expected:
                self.assertTrue(message, "No error message for %s" % (reply))

        # No device ID in the reply or in activation.xml
        self.write_file("activation.xml", activation_xml().replace("<adept:device>%s</adept:device>" % (DEVICE), ""))
        reply = etree.fromstring(fulfillment_reply(good).replace("<device>%s</device>" % (DEVICE), ""))
        server = FakeServer(SUCCESS)
        with patch.object(libadobeFulfill, "send_adept", server.send):
            success, message = quietly(libadobeFulfill.performFulfillmentNotification, reply, True)
        self.assertFalse(success, "No error without a device ID")
        self.assertEqual(server.requests, [], "Sent a notification without a device ID")


    def test_loanReturn(self):
        '''Check if tryReturnBook signs with the key of the account that borrowed the book'''

        # (useByteBooks in the loan record, whose key, return URL, notification URL);
        # loan records from older plugin versions don't have useByteBooks
        cases = [
            (True, "ByteBooks", OPERATOR + "/LoanReturn?ofByteBooks=1", NOTIFY_URL + "?ofByteBooks=1"),
            (False, "Adobe", OPERATOR + "/LoanReturn", NOTIFY_URL),
            (None, "Adobe", OPERATOR + "/LoanReturn", NOTIFY_URL),
        ]

        for use_bytebooks, vendor, return_url, notify_url in cases:
            book = {"user": USER, "device": DEVICE, "loanID": "LOAN-1", "operatorURL": OPERATOR}
            if use_bytebooks is not None:
                book["useByteBooks"] = use_bytebooks
            server = FakeServer(LOAN_RETURN_REPLY)
            notifications = FakeServer(SUCCESS)
            # The return goes to the operator, the notification that its reply asks for to NOTIFY_URL
            send = lambda url, *args, **kwargs: (notifications if url.startswith(NOTIFY_URL) else server).send(url, *args, **kwargs)
            with patch.object(libadobeFulfill, "send_adept", send):
                success, reply = quietly(libadobeFulfill.tryReturnBook, book)

            self.assertTrue(success, "Return failed, useByteBooks=%s: %s" % (use_bytebooks, reply))
            self.assertEqual(self.sent(server), [(return_url, vendor)], "Wrong return request, useByteBooks=%s" % (use_bytebooks))
            request = server.requests[0][1]
            self.assertEqual([request.findtext(ADEPT + tag) for tag in ("user", "device", "loan")], [USER, DEVICE, "LOAN-1"],
                             "Wrong return request, useByteBooks=%s" % (use_bytebooks))
            # The reply asks for a notification, which has to go out the same way
            self.assertEqual(self.sent(notifications), [(notify_url, vendor)], "Wrong notification, useByteBooks=%s" % (use_bytebooks))


    def test_loanReturnErrors(self):
        '''Check if tryReturnBook reports failed returns'''

        book = {"user": USER, "device": DEVICE, "loanID": "LOAN-1", "operatorURL": OPERATOR, "useByteBooks": True}

        # (loan record, server replies, number of requests)
        cases = [
            (book, ['<error xmlns="http://ns.adobe.com/adept" data="E_LOAN_NOT_ON_USER"/>'], 1),
            (book, ["<html>Bad gateway</html>"], 1),
            (book, [libadobe.RequestError("Connection refused")], 1),
            (dict((key, value) for key, value in book.items() if key != "operatorURL"), [], 0),
        ]

        for loan_record, replies, request_count in cases:
            server = FakeServer(*replies)
            with patch.object(libadobeFulfill, "send_adept", server.send):
                success, reply = quietly(libadobeFulfill.tryReturnBook, loan_record)
            self.assertFalse(success, "No error for %r, %r" % (sorted(loan_record), replies))
            self.assertEqual(len(server.requests), request_count, "Wrong number of requests for %r, %r" % (sorted(loan_record), replies))


    def test_sendAdeptTimeLimit(self):
        '''Check if send_adept gives up on a request that takes longer than the time limit'''

        import threading, time
        release = threading.Event()
        self.addCleanup(release.set)    # lets the abandoned request thread end

        def hanging_urlopen(*args, **kwargs):
            # Like a server that keeps sending a byte now and then, but never finishes.
            # It does give up after 2 seconds to not hang a failing test forever.
            release.wait(2)
            raise IOError("released")

        # The request never finishes, so a short time limit is enough for a test that doesn't
        # depend on timing. The thread can't have finished by the time the limit is reached.
        with patch.object(libadobe.ulib, "urlopen", side_effect=hanging_urlopen), \
                patch.object(libadobe, "VAR_HTTP_REQUEST_TIME_LIMIT", 0.01):
            start = time.time()
            with self.assertRaises(libadobe.RequestError) as cm:
                quietly(libadobe.send_adept, "https://example.com/adept", None, True)
            self.assertLess(time.time() - start, 2, "send_adept didn't give up at the time limit")
        self.assertIn("no complete reply within", str(cm.exception))

    def test_httpOnlyURLs(self):
        """Check if the request functions only open HTTP and HTTPS URLs, not local files or other schemes"""

        local_file = os.path.join(self.account_dir, "local.xml")
        with open(local_file, "w") as f:
            f.write('<success xmlns="http://ns.adobe.com/adept"/>')
        output_file = os.path.join(self.account_dir, "download.bin")

        # Real URLs that urllib would open without a network
        for url in ["file://" + local_file, "data:text/plain,PK"]:
            if url.startswith("file:"):
                with self.assertRaises(libadobe.RequestError, msg=url):
                    quietly(libadobe.send_adept, url, "<x/>", False)
            self.assertEqual(quietly(libadobe.sendHTTPRequest_DL2FILE, url, output_file, False), 900, url)
            self.assertFalse(os.path.exists(output_file), url + ": file was downloaded")

        # Other ways to write such URLs. urllib isn't called for them at all.
        rejected = ["FILE://" + local_file, "  file://" + local_file, "<URL:file://" + local_file + ">",
                    "file:" + local_file, "ftp://example.com/book.epub", "data:text/plain,PK"]
        with patch.object(libadobe.ulib, "urlopen", side_effect=IOError("no network in tests")) as urlopen:
            for url in rejected:
                self.assertEqual(quietly(libadobe.sendHTTPRequest_DL2FILE, url, output_file, False), 900, url)
                if "://" in url:
                    # send_adept adds "http://" to URLs without it
                    with self.assertRaises(libadobe.RequestError, msg=url):
                        quietly(libadobe.send_adept, url, "<x/>", False)
            self.assertFalse(urlopen.called, "urlopen was called for a URL that isn't HTTP(S)")

            # HTTP and HTTPS URLs are still requested
            for url in ["http://example.com/a", "HTTPS://example.com/a", " https://example.com/a\n"]:
                urlopen.reset_mock()
                self.assertEqual(quietly(libadobe.sendHTTPRequest_DL2FILE, url, output_file, False), 900, url)
                with self.assertRaises(libadobe.RequestError, msg=url):
                    quietly(libadobe.send_adept, url, "<x/>", False)
                self.assertEqual(urlopen.call_count, 2, url + ": wasn't requested")
