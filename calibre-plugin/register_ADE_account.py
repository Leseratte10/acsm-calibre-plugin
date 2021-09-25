#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is an experimental Python version of libgourou. 
'''


from libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile
from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice

# These are the only two variables you'll need to change
# The mail address and password of your Adobe account to assign. 
# This tool doesn't support anonymous registrations, 
# so it's recommended to make a throwaway Adobe account.

VAR_MAIL = "test@example.com"
VAR_PASS = "mypassword"
#################################################################

def main():
    createDeviceKeyFile()
    createDeviceFile(VAR_HOBBES_VERSION, False)
    success, resp = createUser()
    if (success is False):
        print("Error, couldn't create user: %s" % resp)
        exit(1)

    success, resp = signIn(VAR_MAIL, VAR_PASS)
    if (success is False):
        print("Login unsuccessful: " + resp)
        exit(1)

    success, resp = activateDevice()
    if (success is False):
        print("Couldn't activate device: " + resp)
        exit(1)

    print("Authorized to account " + VAR_MAIL)


if __name__ == "__main__":
    main()