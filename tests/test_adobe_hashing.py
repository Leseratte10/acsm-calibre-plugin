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


class TestAdobeHashing(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

    
    def test_hash_node(self): 
        '''Check if XML hashing works'''

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
        '''Check if XML hashing works for book returns ...'''

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

        self.assertEqual(sha_hash, "8b0a24ba37c4333d93650c6ce52f8ee779f21533", "Invalid SHA hash for node signing (return)")


    def test_hash_node_ultralong(self): 
        '''Check if XML hashing works with long values'''

        # Warning: 
        # ACS (the server) and ADE (the client) hash ultralong values (> 0x7FFF) completely different. 
        # This means that ADE will not be able to sign an XML in the way the server expects it, if it
        # contains text nodes longer than 0x7FFF or attribute values longer than 0xFFFF. 
        # The plugin (and this test case) implement the hashing algorithm the ACS server implements, 
        # even though it differs from ADE, to be compatible with as many ACSM files as possible. 
        # For more information see the warning comments in libadobe.py hash_text_node() and
        # hash_do_append_string().
        

        # XML text elements get split into 0x7FFF chunks.
        mock_xml_str_text = """
        <adept:notification xmlns:adept="http://ns.adobe.com/adept">
        <adept:testCodeForACSMInput>{}</adept:testCodeForACSMInput>
        </adept:notification>
        """.format("A"*70000)

        mock_xml_obj = etree.fromstring(mock_xml_str_text)
        sha_hash = libadobe.hash_node(mock_xml_obj).hexdigest().lower()
        self.assertEqual(sha_hash, "9aea16fae05cc4487153d0bdd07eda8c8974f32e", "Invalid ultralong text hash")

        # XML attribute values limit the length to two bytes (0xFFFF) but still 
        # include the full string in the hash.

        mock_xml_str_text = """
        <adept:notification xmlns:adept="http://ns.adobe.com/adept">
        <adept:testCodeForACSMInput dummy="{}"></adept:testCodeForACSMInput>
        </adept:notification>
        """.format("A"*70000)

        mock_xml_obj = etree.fromstring(mock_xml_str_text)
        sha_hash = libadobe.hash_node(mock_xml_obj).hexdigest().lower()
        self.assertEqual(sha_hash, "a1824db08ec72fc8a03a0bed5fcfdc88e27a157f", "Invalid ultralong attribute value hash")


    def test_hash_node_attributeSortOrder(self): 
        '''Check if XML hashing sorts attributes bytewise by namespace, then name'''

        # "Attributes are sorted first by their namespaces and then by their names; 
        # sorting is done bytewise on UTF-8 representations."
        # Each attribute below is placed so that sorting lxml's raw "{namespace}name" keys
        # would give a different order:
        #  - "http://example.com/a" must come before "http://example.com/a/x" (prefix first),
        #  - attributes without a namespace must all come before namespaced ones, 
        #    including those whose name starts with a non-ASCII character,
        #  - names are compared by UTF-8 bytes: "Alpha" < "zeta" < "\u00e9lan" < "\uf900" < "\U00020000".

        import hashlib

        mock_xml_str = u"""<adept:test xmlns:adept="http://ns.adobe.com/adept" 
            xmlns:a="http://example.com/a" xmlns:ax="http://example.com/a/x" 
            zeta="1" ax:a="2" \u00e9lan="3" a:b="4" Alpha="5" \uf900="6" \U00020000="7"/>"""

        # Same attributes, different order in the source document
        mock_xml_str_reordered = u"""<adept:test xmlns:adept="http://ns.adobe.com/adept" 
            xmlns:a="http://example.com/a" xmlns:ax="http://example.com/a/x" 
            \U00020000="7" a:b="4" \uf900="6" Alpha="5" ax:a="2" zeta="1" \u00e9lan="3"/>"""

        expected_order = [
            (u"", u"Alpha", u"5"),
            (u"", u"zeta", u"1"),
            (u"", u"\u00e9lan", u"3"),
            (u"", u"\uf900", u"6"),
            (u"", u"\U00020000", u"7"),
            (u"http://example.com/a", u"b", u"4"),
            (u"http://example.com/a/x", u"a", u"2"),
        ]

        # Build the expected hash input by hand, independent of the plugin's hashing helpers:
        # each string is a 2-byte big-endian length followed by its UTF-8 bytes.
        def asn_string(value):
            data = value.encode("utf-8")
            return bytearray([len(data) >> 8, len(data) & 0xff]) + bytearray(data)

        expected_stream = bytearray([libadobe.ASN_NS_TAG]) + asn_string(u"http://ns.adobe.com/adept") + asn_string(u"test")
        for namespace, name, value in expected_order:
            expected_stream += bytearray([libadobe.ASN_ATTRIBUTE]) + asn_string(namespace) + asn_string(name) + asn_string(value)
        expected_stream += bytearray([libadobe.ASN_CHILD, libadobe.ASN_END_TAG])

        expected_hash = hashlib.sha1(bytes(expected_stream)).hexdigest().lower()

        sha_hash = libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()
        self.assertEqual(sha_hash, expected_hash, "Attributes are not sorted bytewise by namespace, then name")

        sha_hash_reordered = libadobe.hash_node(etree.fromstring(mock_xml_str_reordered)).hexdigest().lower()
        self.assertEqual(sha_hash_reordered, expected_hash, "Attribute order in the document changes the hash")


    def test_hash_node_nonASCII(self): 
        '''Check if XML hashing works with non-ASCII text'''

        mock_xml_str = u"""<fulfillmentToken fulfillmentType="free" auth="user" xmlns="http://ns.adobe.com/adept">
          <resourceItemInfo><metadata>
            <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">Caf\u00e9 au lait</dc:title>
          </metadata></resourceItemInfo></fulfillmentToken>"""

        sha_hash = libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()
        self.assertEqual(sha_hash, "1b3cdf43f9f7d296d91476b2c05d0b5dd58f9c00", "Invalid SHA hash for node signing (non-ASCII text)")


    def test_hash_node_comment(self):
        '''Check if XML hashing skips XML comments and processing instructions'''

        mock_xml_str = """
        <fulfillmentToken fulfillmentType="free" auth="user" xmlns="http://ns.adobe.com/adept">
          <!-- Generated by the test suite -->
          <resourceItemInfo>
            <?acsm-generator test-suite?>
            <resource>urn:uuid:6f300313-d746-44b6-8c88-5b2afa8e0909</resource>
            <!-- Only one item -->
            <resourceItem>1</resourceItem>
          </resourceItemInfo></fulfillmentToken>"""

        mock_xml_str_without_comments = """
        <fulfillmentToken fulfillmentType="free" auth="user" xmlns="http://ns.adobe.com/adept">
          <resourceItemInfo>
            <resource>urn:uuid:6f300313-d746-44b6-8c88-5b2afa8e0909</resource>
            <resourceItem>1</resourceItem>
          </resourceItemInfo></fulfillmentToken>"""

        sha_hash = libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()
        expected_hash = libadobe.hash_node(etree.fromstring(mock_xml_str_without_comments)).hexdigest().lower()
        self.assertEqual(sha_hash, expected_hash, "XML comments change the hash")

        # The text after a comment has to be hashed as well. lxml stores it in the
        # comment's .tail instead of the element's .text, so skipping the comment
        # alone would drop the text from the hash.

        mock_xml_str = """
        <operatorURL xmlns="http://ns.adobe.com/adept"><!-- Test server -->https://example.com/fulfillment</operatorURL>
        """
        mock_xml_str_without_comments = """
        <operatorURL xmlns="http://ns.adobe.com/adept">https://example.com/fulfillment</operatorURL>
        """

        sha_hash = libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()
        expected_hash = libadobe.hash_node(etree.fromstring(mock_xml_str_without_comments)).hexdigest().lower()
        self.assertEqual(sha_hash, expected_hash, "The text after an XML comment isn't hashed")

    def test_hash_node_textAroundComment(self):
        '''Check if text that an XML comment splits in two is hashed as one text node'''

        # The server expects the text in front of and after a comment to be hashed as
        # one text node, as if the comment wasn't in the XML at all. It rejects the
        # request if they're hashed as two text nodes.

        mock_xml_str = """<title xmlns="http://ns.adobe.com/adept">Book <!-- comment --> title</title>"""

        # Without the comment, both spaces stay. Only the ends of a text node are trimmed.
        mock_xml_str_without_comments = """<title xmlns="http://ns.adobe.com/adept">Book  title</title>"""

        sha_hash = libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()
        expected_hash = libadobe.hash_node(etree.fromstring(mock_xml_str_without_comments)).hexdigest().lower()
        self.assertEqual(sha_hash, expected_hash, "Text around a comment isn't hashed as one text node")

    def test_hash_node_entity(self):
        '''Check if XML hashing rejects entity references instead of crashing'''

        # The safe parser keeps references to entities from a DOCTYPE as entity nodes
        mock_xml_str = """<!DOCTYPE title [<!ENTITY name "Book">]>
        <title xmlns="http://ns.adobe.com/adept">&name; title</title>"""

        node = etree.fromstring(mock_xml_str, parser=libadobe.safe_xml_parser())
        self.assertRaises(ValueError, libadobe.hash_node, node)

    def test_hash_node_trimsLikeJava(self):
        '''Check if XML hashing trims text nodes like the server does (Java's String.strip())'''

        # The server trims what Java's Character.isWhitespace() counts as whitespace from
        # both ends of a text node: more than XML whitespace (U+3000, for example), but not
        # the non-breaking spaces. Neither Python's strip() nor strip(" \t\r\n") does the
        # same, and the server rejects the signature if a text node begins or ends with a
        # character they treat differently.

        import hashlib

        # Build the expected hash input by hand: each string is a 2-byte big-endian
        # length followed by its UTF-8 bytes.
        def asn_string(value):
            data = value.encode("utf-8")
            return bytearray([len(data) >> 8, len(data) & 0xff]) + bytearray(data)

        def expected_hash(text):
            stream = bytearray([libadobe.ASN_NS_TAG]) + asn_string(u"http://ns.adobe.com/adept") + asn_string(u"title")
            stream += bytearray([libadobe.ASN_CHILD])
            if text is not None:
                stream += bytearray([libadobe.ASN_TEXT]) + asn_string(text)
            stream += bytearray([libadobe.ASN_END_TAG])
            return hashlib.sha1(bytes(stream)).hexdigest().lower()

        def sha_hash(text_xml):
            mock_xml_str = u"""<title xmlns="http://ns.adobe.com/adept">%s</title>""" % (text_xml)
            return libadobe.hash_node(etree.fromstring(mock_xml_str)).hexdigest().lower()

        # XML whitespace is trimmed. A CR only gets through the parser as a character reference.
        self.assertEqual(sha_hash(u" \t\n&#13;Book title&#13;\n\t "), expected_hash(u"Book title"), "XML whitespace isn't trimmed")
        self.assertEqual(sha_hash(u" \t\n&#13; "), expected_hash(None), "A text node with only XML whitespace is hashed")

        # The other characters Java counts as whitespace are trimmed as well
        for char in u"\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2008\u2009\u200a\u2028\u2029\u205f\u3000":
            self.assertEqual(sha_hash(u"%s Book title %s" % (char, char)), expected_hash(u"Book title"), "U+%04X isn't trimmed" % ord(char))
            self.assertEqual(sha_hash(char), expected_hash(None), "A text node with only U+%04X is hashed" % ord(char))

        # Java doesn't count the non-breaking spaces and U+0085 as whitespace (Python's strip() does)
        for char in u"\u00a0\u2007\u202f\u0085":
            self.assertEqual(sha_hash(u" %sBook title%s\n" % (char, char)), expected_hash(u"%sBook title%s" % (char, char)), "U+%04X is trimmed" % ord(char))
            self.assertEqual(sha_hash(char), expected_hash(char), "A text node with only U+%04X isn't hashed" % ord(char))

        # Trimming stops at the first character that isn't whitespace for Java. The server
        # rejected a text node ending in U+00A0 U+3000 when it was trimmed any other way.
        self.assertEqual(sha_hash(u"\u3000\u00a0Book title\u00a0\u3000"), expected_hash(u"\u00a0Book title\u00a0"), "Trimming doesn't stop at a no-break space")

