#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is an experimental Python version of libgourou. 
'''

# pyright: reportUndefinedVariable=false

import sys, os
if sys.version_info[0] < 3:
    print("This script requires Python 3.")
    exit(1)

import zipfile
from lxml import etree

from libadobe import sendHTTPRequest
from libadobeFulfill import buildRights, fulfill
from libpdf import patch_drm_into_pdf, prepare_string_from_xml

FILE_DEVICEKEY = "devicesalt"
FILE_DEVICEXML = "device.xml"
FILE_ACTIVATIONXML = "activation.xml"

#######################################################################


def download(replyData):
    # replyData: str
    adobe_fulfill_response = etree.fromstring(replyData)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    adDC = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

    print (replyData)


    metadata_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata")))
    download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
    resource_id = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("resource"))).text
    license_token_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))

    rights_xml_str = buildRights(license_token_node)

    if (rights_xml_str is None):
        print("Building rights.xml failed!")
        exit(1)

    book_name = None
    author = "None"
    title = "None"
    try: 
        book_name = metadata_node.find("./%s" % (adDC("title"))).text
    except: 
        book_name = "Book"
    
    try: 
        title = metadata_node.find("./%s" % (adDC("title"))).text
        author = metadata_node.find("./%s" % (adDC("creator"))).text

        title = title.replace("(", "").replace(")", "").replace("/", "")
        author = author.replace("(", "").replace(")", "").replace("/", "")

    except:
        pass

    # Download eBook: 

    print(download_url)

    book_content = sendHTTPRequest(download_url)
    filetype = ".bin"
    
    if (book_content.startswith(b"PK")):
        print("That's a ZIP file -> EPUB")
        filetype = ".epub"
    elif (book_content.startswith(b"%PDF")):
        print("That's a PDF file")
        filetype = ".pdf"

    filename = book_name + filetype

    # Store book:
    f = open(filename, "wb")
    f.write(book_content)
    f.close()

    if filetype == ".epub":
        # Store EPUB rights / encryption stuff
        zf = zipfile.ZipFile(filename, "a")
        zf.writestr("META-INF/rights.xml", rights_xml_str)
        zf.close()

        print("File successfully fulfilled to " + filename)
        exit(0)
    
    elif filetype == ".pdf":
        print("Successfully downloaded PDF, patching encryption ...")
        
        os.rename(filename, "tmp_" + filename)
        patch_drm_into_pdf("tmp_" + filename, prepare_string_from_xml(rights_xml_str, author, title), filename)
        os.remove("tmp_" + filename)
        print("File successfully fulfilled to " + filename)
        exit(0)
    else: 
        print("Error: Weird filetype")
        exit(1)


def main():
    print("Fulfilling book ...")
    success, replyData = fulfill("URLLink.acsm")
    if (success is False):
        print("Hey, that didn't work!")
        print(replyData)
    else: 
        print("Downloading book ...")
        download(replyData)


if __name__ == "__main__":
    main()