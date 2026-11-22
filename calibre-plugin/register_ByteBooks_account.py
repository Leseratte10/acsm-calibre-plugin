#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import getpass, sys

from libadobe import createDeviceKeyFile
from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice

# These are the only two variables you'll need to change
# The mail address and password of your ByteBooks account to assign. 
# This tool doesn't support anonymous registrations, 
# so it's recommended to make a throwaway ByteBooks account.

VAR_MAIL = ""
VAR_PASS = ""
#################################################################

def main():

    global VAR_MAIL
    global VAR_PASS


    if (VAR_MAIL == ""):
        VAR_MAIL = input("Please enter your AdobeID (or press enter for anonymous auth): ")
    
    if (VAR_PASS == "" and VAR_MAIL != ""):
        VAR_PASS = getpass.getpass("Please enter the password for your AdobeID: ")

    if (VAR_MAIL != "" and VAR_PASS == ""):
        print("Empty password, aborting")
        exit(1)


    createDeviceKeyFile()
    
    success = createDeviceFile(True, 0)
    if (success is False):
        print("Error, couldn't create device file.")
        exit(1)

    success, resp = createUser(0, None, None)
    if (success is False):
        print("Error, couldn't create user: %s" % resp)
        exit(1)

    if VAR_MAIL == "": 
        success, resp = signIn("anonymous", "", "")
    else:    
        success, resp = signIn("AdobeID", VAR_MAIL, VAR_PASS)
        
    if (success is False):
        print("Login unsuccessful: " + resp)
        exit(1)

    success, resp = activateDevice(0, None)
    if (success is False):
        print("Couldn't activate device: " + resp)
        exit(1)

    print("Authorized to account " + VAR_MAIL)


if __name__ == "__main__":
    main()