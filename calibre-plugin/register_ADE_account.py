#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is an experimental Python version of libgourou. 
'''

import getpass, sys

if sys.version_info[0] < 3:
    print("This script requires Python 3.")
    exit(1)

from libadobe import createDeviceKeyFile, VAR_VER_SUPP_CONFIG_NAMES
from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice

# These are the only two variables you'll need to change
# The mail address and password of your Adobe account to assign. 
# This tool doesn't support anonymous registrations, 
# so it's recommended to make a throwaway Adobe account.

VAR_MAIL = ""
VAR_PASS = ""
VAR_VER = None # 1 for ADE2.0, 2 for ADE3.0
#################################################################

def main():

    global VAR_MAIL
    global VAR_PASS
    global VAR_VER


    if (VAR_MAIL == ""):
        VAR_MAIL = input("Please enter your AdobeID: ")
    
    if (VAR_PASS == ""):
        VAR_PASS = getpass.getpass("Please enter the password for your AdobeID: ")

    if (VAR_VER is None):
        VAR_VER = int(input("Please enter '1' for ADE 2.0 or '2' for ADE 3.0: "))

    if VAR_VER >= len(VAR_VER_SUPP_CONFIG_NAMES):
        print("Invalid version")
        exit(1)

    if (VAR_MAIL == "" or VAR_PASS == ""):
        print("Empty credential, aborting")
        exit(1)


    createDeviceKeyFile()
    
    success = createDeviceFile(True, VAR_VER)
    if (success is False):
        print("Error, couldn't create device file.")
        exit(1)

    success, resp = createUser(VAR_VER, None)
    if (success is False):
        print("Error, couldn't create user: %s" % resp)
        exit(1)

    success, resp = signIn("AdobeID", VAR_MAIL, VAR_PASS)
    if (success is False):
        print("Login unsuccessful: " + resp)
        exit(1)

    success, resp = activateDevice(VAR_VER)
    if (success is False):
        print("Couldn't activate device: " + resp)
        exit(1)

    print("Authorized to account " + VAR_MAIL)


if __name__ == "__main__":
    main()