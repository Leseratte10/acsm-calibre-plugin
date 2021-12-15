#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is an experimental Python version of libgourou. 
'''

# pyright: reportUndefinedVariable=false

import sys, os, time, shutil
if sys.version_info[0] < 3:
    print("This script requires Python 3.")
    exit(1)

import zipfile
from lxml import etree

from libadobe import sendHTTPRequest_DL2FILE
from libadobeFulfill import buildRights, fulfill
from libpdf import patch_drm_into_pdf

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


    download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
    resource_id = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("resource"))).text
    license_token_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))

    rights_xml_str = buildRights(license_token_node)

    if (rights_xml_str is None):
        print("Building rights.xml failed!")
        exit(1)

    book_name = None

    try: 
        metadata_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata")))
        book_name = metadata_node.find("./%s" % (adDC("title"))).text
    except: 
        book_name = "Book"
    

    # Download eBook: 

    print(download_url)

    filename_tmp = book_name + ".tmp"

    dl_start_time = int(time.time() * 1000)
    ret = sendHTTPRequest_DL2FILE(download_url, filename_tmp)
    dl_end_time = int(time.time() * 1000)
    print("Download took %d milliseconds" % (dl_end_time - dl_start_time))

    if (ret != 200):
        print("Download failed with error %d" % (ret))
        exit()

    with open(filename_tmp, "rb") as f:
        book_content = f.read(10)

    filetype = ".bin"
    
    if (book_content.startswith(b"PK")):
        print("That's a ZIP file -> EPUB")
        filetype = ".epub"
    elif (book_content.startswith(b"%PDF")):
        print("That's a PDF file")
        filetype = ".pdf"

    filename = book_name + filetype
    shutil.move(filename_tmp, filename)

    if filetype == ".epub":
        # Store EPUB rights / encryption stuff
        zf = zipfile.ZipFile(filename, "a")
        zf.writestr("META-INF/rights.xml", rights_xml_str)
        zf.close()

        print("File successfully fulfilled to " + filename)
        exit(0)
    
    elif filetype == ".pdf":
        print("Successfully downloaded PDF, patching encryption ...")

        adobe_fulfill_response = etree.fromstring(rights_xml_str)
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        resource = adobe_fulfill_response.find("./%s/%s" % (adNS("licenseToken"), adNS("resource"))).text
        
        os.rename(filename, "tmp_" + filename)
        ret = patch_drm_into_pdf("tmp_" + filename, rights_xml_str, filename, resource)
        os.remove("tmp_" + filename)
        if (ret):
            print("File successfully fulfilled to " + filename)
        else: 
            print("Errors occurred while patching " + filename)
            exit(1)
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