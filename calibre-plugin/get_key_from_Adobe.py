#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Run this tool to download the eBook DER encryption key
for a given ADE account from the Adobe server. 

I am not responsible if Adobe does ban your Account for using
nonstandard software, though in all my previous tests that has
never happened. 

Though I would suggest not running this script multiple times - 
just run it once and then make enough backups of the key file.

'''

import sys, getpass, tempfile

if sys.version_info[0] < 3:
    print("This script requires Python 3.")
    exit(1)

from libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
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

    filename = "adobekey_" + VAR_MAIL + ".der"

    with tempfile.TemporaryDirectory() as temp_dir:
        update_account_path(temp_dir)

        print ("Preparing keys ...")

        createDeviceKeyFile()
        createDeviceFile(VAR_HOBBES_VERSION, True)
        success, resp = createUser()
        if (success is False):
            print("Error, couldn't create user: %s" % resp)
            exit(1)

        print("Logging in ...")

        success, resp = signIn(VAR_MAIL, VAR_PASS)
        if (success is False):
            print("Login unsuccessful: " + resp)
            exit(1)

        print("Exporting keys ...")

        try: 
            account_uuid = getAccountUUID()
            if (account_uuid is not None):
                filename = "adobekey_" + VAR_MAIL + "_uuid_" + account_uuid + ".der"
        except: 
            pass

        success = exportAccountEncryptionKeyDER(filename)
        if (success is False):
            print("Couldn't export key.")
            exit(1)


    print("Successfully exported key for account " + VAR_MAIL + " to file " + filename)


if __name__ == "__main__":
    main()