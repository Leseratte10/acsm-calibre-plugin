#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, getpass

from acsm_input.libadobe import createDeviceKeyFile
from acsm_input.libadobeAccount import createDeviceFile, createUser, signIn, activateDevice

try:
    # Python 2: input() runs what you type as Python code, raw_input() returns the text
    input = raw_input           # type: ignore
except NameError:
    pass

# These are the only two variables you'll need to change
# The mail address and password of your ByteBooks account to assign. 


VAR_MAIL = u""
VAR_PASS = u""
#################################################################

def typed_text(value):
    # type: (str|bytes) -> str
    # On Python 2, raw_input and getpass return what was typed as bytes in the terminal's
    # encoding. signIn needs text, or a non-ASCII address or password crashes it.
    if isinstance(value, bytes):
        return value.decode(sys.stdin.encoding or "utf-8")
    return value

def main():

    global VAR_MAIL
    global VAR_PASS


    if (VAR_MAIL == ""):
        VAR_MAIL = typed_text(input("Please enter your AdobeID (or press enter for anonymous auth): "))
    
    if (VAR_PASS == "" and VAR_MAIL != ""):
        VAR_PASS = typed_text(getpass.getpass("Please enter the password for your AdobeID: "))

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