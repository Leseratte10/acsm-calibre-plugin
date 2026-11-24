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
from acsm_input.libpdf import trim_encrypt_string, cleanup_encrypt_element, deflate_and_base64_encode  # type: ignore


class TestPDFFormat(unittest.TestCase):

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

        self.assertEqual(trim_encrypt_string(input), output, "trim didn't remove trailing junk")

        input = "PrefixJunk123<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"
        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"

        self.assertEqual(trim_encrypt_string(input), output, "trim didn't remove leading junk")

    def test_pdf_cleanupEncrypt(self): 
        '''Check if PDF encryption string spacing code is working properly'''

        self.assertEqual(cleanup_encrypt_element("ID[<1111><2222>]"),       "ID[<1111> <2222>]", "angle bracket spacing invalid")
        self.assertEqual(cleanup_encrypt_element("ID[  <1111> <2222>]  "),  "ID[<1111> <2222>]", "square bracket spacing invalid")

    def test_pdf_deflateCompression(self): 
        '''Check if PDF rights.xml deflare code is working properly'''

        self.assertEqual(deflate_and_base64_encode(b""),                  b"AwA=",                  "deflate code error in empty string")
        self.assertEqual(deflate_and_base64_encode(b"Hello world"),       b"80jNyclXKM8vykkBAA==",  "deflate code error")
        self.assertEqual(deflate_and_base64_encode(b"Example AAAAAAAAA"), b"c61IzC3ISVVwhAEA",      "deflate code error")

