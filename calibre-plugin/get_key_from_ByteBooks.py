#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

'''
Run this tool to download the eBook DER encryption key
for a given account from the ByteBooks server. 

I am not responsible if ByteBooks or Adobe does ban your Account 
for using nonstandard software, though in all my previous tests 
that has never happened. 

Though I would suggest not running this script multiple times - 
just run it once and then make enough backups of the key file.

'''

import sys, getpass, tempfile

if sys.version_info[0] < 3:
    print("This script requires Python 3.")
    exit(1)

from libadobe import createDeviceKeyFile, update_account_path
from libadobeAccount import createDeviceFile, createUser, signIn, exportAccountEncryptionKeyDER, getAccountUUID

# These are the only two variables you'll need to change
# The mail address and password of your Adobe account 

VAR_MAIL = ""
VAR_PASS = ""

#################################################################

def main():
    global VAR_MAIL
    global VAR_PASS

    if (VAR_MAIL == ""):
        VAR_MAIL = input("Please enter your AdobeID: ")
    
    if (VAR_PASS == ""):
        VAR_PASS = getpass.getpass("Please enter the password for your AdobeID: ")


    if (VAR_MAIL == "" or VAR_PASS == ""):
        print("Empty credential, aborting")
        exit(1)

    with tempfile.TemporaryDirectory() as temp_dir:
        update_account_path(temp_dir)

        print ("Preparing keys ...")

        createDeviceKeyFile()
        success = createDeviceFile(True, 0)
        if (success is False):
            print("Error, couldn't create device file.")
            exit(1)


        success, resp = createUser(0, None)
        if (success is False):
            print("Error, couldn't create user: %s" % resp)
            exit(1)

        print("Logging in ...")

        success, resp = signIn("AdobeID", VAR_MAIL, VAR_PASS)
        if (success is False):
            print("Login unsuccessful: " + resp)
            exit(1)

        print("Exporting keys ...")

        filename = "bytebooks_key_" + VAR_MAIL + ".der"
        try: 
            account_uuid = getAccountUUID()
            if (account_uuid is not None):
                filename = "bytebooks_key_" + VAR_MAIL + "_uuid_" + account_uuid + ".der"
        except: 
            pass

        success = exportAccountEncryptionKeyDER(filename)
        if (success is False):
            print("Couldn't export key.")
            exit(1)


    print("Successfully exported key for account " + VAR_MAIL + " to file " + filename)


if __name__ == "__main__":
    main()