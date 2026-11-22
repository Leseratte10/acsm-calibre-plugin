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
from freezegun import freeze_time
from lxml import etree



import libadobeLoans        # type: ignore
import libadobeFulfill      # type: ignore



class TestPluginInterface(unittest.TestCase): 

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

    @unittest.skipIf(sys.platform.startswith("win"), "Does not work on Windows due to file permissions.")
    @unittest.skipIf(sys.version_info >= (3, 14, 0), "This is currently buggy, see cpython bug #152445")
    def test_addFileToZipIn1970(self):
        '''Check if ZIP file writing works in 1970'''

        source_date_epoch_old = None

        if 'SOURCE_DATE_EPOCH' in os.environ:
            source_date_epoch_old = os.environ['SOURCE_DATE_EPOCH']
        
        os.environ['SOURCE_DATE_EPOCH'] = '1'

        import zipfile, tempfile, struct
        try: 
            tf = tempfile.NamedTemporaryFile(suffix='.zip')
            if sys.version_info < (3, 8, 0):
                zf = zipfile.ZipFile(tf.name, "w")
            else: 
                zf = zipfile.ZipFile(tf.name, "w", strict_timestamps=False)
            zf.writestr("test.xml", "Hallo Welt")
            zf.close()
        except struct.error:
            self.fail("Failed to add file to ZIP archive")
        finally: 
            if source_date_epoch_old is not None: 
                os.environ['SOURCE_DATE_EPOCH'] = source_date_epoch_old


    @freeze_time("2022-07-01 07:34:32.000000")
    def test_loanListTimeManagementCorrect(self):
        '''Check if timestamps for book loans are handled correctly'''

        book_not_expired = [
            {
                "book_name": "Book title for test",
                "device": 'urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84',
                "user": 'urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa',
                "operatorURL": 'https://acs.example.com/fulfillment',
                "loanID": '34659b20-92c8-4004-9fd8-c5174e7eed47-00010214',
                "validUntil": '2022-07-01T07:36:00Z', 
                "useByteBooks": True
            }
        ]

        book_expired = [
            {
                "book_name": "Book title for test",
                "device": 'urn:uuid:83681cbb-b6df-44a3-a423-c2b37ba66e84',
                "user": 'urn:uuid:2bd57a81-6192-4a1b-8eb2-64e2d197f9fa',
                "operatorURL": 'https://acs.example.com/fulfillment',
                "loanID": '34659b20-92c8-4004-9fd8-c5174e7eed47-00010214',
                "validUntil": '2022-07-01T07:32:00Z', 
                "useByteBooks": True
            }
        ]
        self.assertEqual(libadobeLoans.remove_overdue_books_from_list(book_not_expired), book_not_expired)
        self.assertEqual(libadobeLoans.remove_overdue_books_from_list(book_expired), [])


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
            "validUntil": '2022-07-03T01:14:42Z', 
            "useByteBooks": True
        }

        self.assertEqual(extracted_token, expected_token, "Loan record generator broken")


