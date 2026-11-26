#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''


import sys, os, re, time, shutil

import zipfile
from lxml import etree

from acsm_input.libadobe import sendHTTPRequest_DL2FILE, safe_xml_parser, DOWNLOAD_FILE_ERROR
from acsm_input.libadobeFulfill import buildRights, fulfill
from acsm_input.libpdf import patch_drm_into_pdf


#######################################################################


# Names Windows reserves for devices, also with an extension like "CON.epub"
WINDOWS_RESERVED_NAMES = ["CON", "PRN", "AUX", "NUL"] + ["COM%d" % i for i in range(1, 10)] + ["LPT%d" % i for i in range(1, 10)]


def safe_file_name(title):
    # type: (str|None) -> str
    # Turns a book title into the name of a file in the current folder that works on
    # Windows, macOS and Linux. Path separators, ":" (drive letters and NTFS streams) and
    # the other characters Windows doesn't allow are replaced, reserved device names get a
    # prefix, and long titles are shortened so that the name still fits into 255 bytes
    # with the extension and the "tmp_" prefix.

    name = re.sub(r'[\x00-\x1f<>:"/\\|?*]', "_", title or "")

    # Windows drops dots and spaces at the end, and a dot at the start hides the file
    name = name.strip(" .")

    # At most 200 bytes of UTF-8, without cutting a character in half
    name = name.encode("utf-8")[:200].decode("utf-8", "ignore").rstrip(" .")

    if name.split(".")[0].strip().upper() in WINDOWS_RESERVED_NAMES:
        name = "_" + name

    return name or "Book"


def download(replyData):
    # replyData: str
    adobe_fulfill_response = etree.fromstring(replyData, parser=safe_xml_parser())
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    adDC = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

    print (replyData)


    download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
    #resource_id = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("resource"))).text
    license_token_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))

    rights_xml_str = buildRights(license_token_node)

    if (rights_xml_str is None):
        print("Building rights.xml failed!")
        return False

    book_name = None

    try: 
        metadata_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata")))
        book_name = metadata_node.find("./%s" % (adDC("title"))).text
    except: 
        book_name = "Book"

    # The title becomes the file name
    book_name = safe_file_name(book_name)
    

    # Download eBook: 

    print(download_url)

    filename_tmp = book_name + ".tmp"

    dl_start_time = int(time.time() * 1000)
    ret = sendHTTPRequest_DL2FILE(download_url, filename_tmp, False)
    dl_end_time = int(time.time() * 1000)
    print("Download took %d milliseconds" % (dl_end_time - dl_start_time))

    if (ret == DOWNLOAD_FILE_ERROR):
        print("Couldn't save the downloaded book")
        return False

    if (ret != 200):
        print("Download failed with error %d" % (ret))
        return False

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
    try: 
        shutil.move(filename_tmp, filename)
    except: 
        shutil.move(filename_tmp, "Book" + filetype)
        filename = "Book" + filetype


    if filetype == ".epub":
        # Store EPUB rights / encryption stuff
        zf = zipfile.ZipFile(filename, "a")
        zf.writestr("META-INF/rights.xml", rights_xml_str)
        zf.close()

        print("File successfully fulfilled to " + filename)
        return True
    
    elif filetype == ".pdf":
        print("Successfully downloaded PDF, patching encryption ...")

        adobe_fulfill_response = etree.fromstring(rights_xml_str, parser=safe_xml_parser())
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        resource = adobe_fulfill_response.find("./%s/%s" % (adNS("licenseToken"), adNS("resource"))).text
        
        os.rename(filename, "tmp_" + filename)
        ret = patch_drm_into_pdf("tmp_" + filename, rights_xml_str, filename, resource)
        os.remove("tmp_" + filename)
        if (ret):
            print("File successfully fulfilled to " + filename)
            return True
        else: 
            print("Errors occurred while patching " + filename)
            return False

    else: 
        print("Error: Weird filetype")
        return False


def main():

    if len(sys.argv) < 2:
        files = [ "URLLink.acsm" ]
    else: 
        files = sys.argv[1:]

    for file in files:

        print("Fulfilling book '" + file + "' ...")
        success, replyData = fulfill(file)
        if (success is False):
            print("Hey, that didn't work!")
            print(replyData)
        else: 
            print("Downloading book '" + file + "' ...")
            success = download(replyData)
            if (success is False):
                print("That didn't work!")



if __name__ == "__main__":
    main()