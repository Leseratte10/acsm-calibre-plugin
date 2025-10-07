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

        JSON_PATH_OLD = os.path.join("plugins", "deacsm.json")
        JSON_PATH = os.path.join("plugins", "ACSMInput", "ACSMInput.json")

        if os.path.exists(os.path.join(config_dir, JSON_PATH_OLD)):
            # If the file exists in the old location, use that.
            JSON_PATH = JSON_PATH_OLD

        self.deacsmprefs = JSONConfig(JSON_PATH)

        self.deacsmprefs.defaults['configured'] = False

        self.deacsmprefs.defaults['notify_fulfillment'] = True
        self.deacsmprefs.defaults['detailed_logging'] = False
        self.deacsmprefs.defaults['delete_acsm_after_fulfill'] = False

        self.deacsmprefs.defaults['list_of_rented_books'] = []

        if self.deacsmprefs['list_of_rented_books'] == []:
            self.deacsmprefs['list_of_rented_books'] = []



        self.__pluginsdir = os.path.join(config_dir,"plugins")

        success = False
        # Try to find an existing account folder; first in DeACSM, then in ACSMInput
        for f in ["DeACSM", "ACSMInput"]:
            self.__maindir = os.path.join(self.__pluginsdir, f)
            self.__accountdir = os.path.join(self.__maindir,"account")
            if os.path.exists(self.__accountdir):
                self.deacsmprefs.defaults['path_to_account_data'] = self.__accountdir
                success = True
                break

        if not success:
            # We did not find an account folder. See if we can create one ...
            self.__maindir = os.path.join(self.__pluginsdir, "ACSMInput")
            self.__accountdir = os.path.join(self.__maindir,"account")
            if os.path.exists(self.__maindir):
                os.mkdir(self.__accountdir)
                self.deacsmprefs.defaults['path_to_account_data'] = self.__accountdir
                success = True

        if not success:        
            raise Exception("Why does the account folder not exist?")
            

    def refresh(self):
        return self.deacsmprefs.refresh()

    def commit(self):
        return self.deacsmprefs.commit()
    
    def __getitem__(self,kind = None):
        if kind is not None:
            return self.deacsmprefs[kind]
        return self.deacsmprefs

    def set(self, kind, value):
        self.deacsmprefs[kind] = value

    def writeprefs(self,value = True):
        self.deacsmprefs['configured'] = value

    def addnamedvaluetoprefs(self, prefkind, keyname, keyvalue):
        try:
            if keyvalue not in self.deacsmprefs[prefkind].values():
                # ensure that the keyname is unique
                # by adding a number (starting with 2) to the name if it is not
                namecount = 1
                newname = keyname
                while newname in self.deacsmprefs[prefkind]:
                    namecount += 1
                    newname = "{0:s}_{1:d}".format(keyname,namecount)
                # add to the preferences
                self.deacsmprefs[prefkind][newname] = keyvalue
                return (True, newname)
        except:
            traceback.print_exc()
            pass
        return (False, keyname)

    def addvaluetoprefs(self, prefkind, prefsvalue):
        # ensure the keyvalue isn't already in the preferences
        try:
            if prefsvalue not in self.deacsmprefs[prefkind]:
                self.deacsmprefs[prefkind].append(prefsvalue)
                return True
        except:
            traceback.print_exc()
        return False

