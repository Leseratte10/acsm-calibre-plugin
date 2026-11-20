#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2024 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

# Standard Python modules.
import os
import traceback

from calibre.utils.config import JSONConfig, config_dir  # type: ignore


class ACSMInput_Prefs():
    def __init__(self):

        JSON_PATH = os.path.join("plugins", "ACSMInput", "ACSMInput.json")

        self.acsmprefs = JSONConfig(JSON_PATH)

        self.acsmprefs.defaults['configured'] = False

        self.acsmprefs.defaults['notify_fulfillment'] = True
        self.acsmprefs.defaults['detailed_logging'] = False
        self.acsmprefs.defaults['delete_acsm_after_fulfill'] = False

        self.acsmprefs.defaults['list_of_rented_books'] = []

        if self.acsmprefs['list_of_rented_books'] == []:
            self.acsmprefs['list_of_rented_books'] = []



        self.__pluginsdir = os.path.join(config_dir,"plugins")

        success = False
        # Try to find an existing account folder; first in DeACSM, then in ACSMInput
        self.__maindir = os.path.join(self.__pluginsdir, "ACSMInput")
        self.__accountdir = os.path.join(self.__maindir,"account")

        if os.path.exists(self.__accountdir):
            self.acsmprefs.defaults['path_to_account_data'] = self.__accountdir
            success = True

        if not success:
            # We did not find an account folder. Creating it.
            if os.path.exists(self.__maindir):
                os.mkdir(self.__accountdir)
                self.acsmprefs.defaults['path_to_account_data'] = self.__accountdir
                success = True

        if not success:        
            raise Exception("Why does the account folder not exist?")
            

    def refresh(self):
        return self.acsmprefs.refresh()

    def commit(self):
        return self.acsmprefs.commit()
    
    def __getitem__(self,kind = None):
        if kind is not None:
            return self.acsmprefs[kind]
        return self.acsmprefs

    def set(self, kind, value):
        self.acsmprefs[kind] = value

    def writeprefs(self,value = True):
        self.acsmprefs['configured'] = value

    def addnamedvaluetoprefs(self, prefkind, keyname, keyvalue):
        try:
            if keyvalue not in self.acsmprefs[prefkind].values():
                # ensure that the keyname is unique
                # by adding a number (starting with 2) to the name if it is not
                namecount = 1
                newname = keyname
                while newname in self.acsmprefs[prefkind]:
                    namecount += 1
                    newname = "{0:s}_{1:d}".format(keyname,namecount)
                # add to the preferences
                self.acsmprefs[prefkind][newname] = keyvalue
                return (True, newname)
        except:
            traceback.print_exc()
            pass
        return (False, keyname)

    def addvaluetoprefs(self, prefkind, prefsvalue):
        # ensure the keyvalue isn't already in the preferences
        try:
            if prefsvalue not in self.acsmprefs[prefkind]:
                self.acsmprefs[prefkind].append(prefsvalue)
                return True
        except:
            traceback.print_exc()
        return False

