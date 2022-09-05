#!/usr/bin/env python3
# -*- coding: utf-8 -*-



# Standard Python modules.
import os
import traceback

from calibre.utils.config import JSONConfig, config_dir  # type: ignore
from calibre.constants import iswindows                  # type: ignore


class ACSMInput_Prefs():
    def __init__(self):

        JSON_PATH_OLD = os.path.join("plugins", "deacsm.json")
        JSON_PATH = os.path.join("plugins", "ACSMInput", "ACSMInput.json")

        if os.path.exists(JSON_PATH_OLD) and not os.path.exists(JSON_PATH):
            os.rename(JSON_PATH_OLD, JSON_PATH)
            if not iswindows:
                os.symlink(JSON_PATH_OLD, JSON_PATH)

        self.deacsmprefs = JSONConfig(JSON_PATH)

        self.deacsmprefs.defaults['configured'] = False

        self.deacsmprefs.defaults['notify_fulfillment'] = True
        self.deacsmprefs.defaults['detailed_logging'] = False
        self.deacsmprefs.defaults['delete_acsm_after_fulfill'] = False

        self.deacsmprefs.defaults['list_of_rented_books'] = []

        if self.deacsmprefs['list_of_rented_books'] == []:
            self.deacsmprefs['list_of_rented_books'] = []



        self.pluginsdir = os.path.join(config_dir,"plugins")
        self.maindir = os.path.join(self.pluginsdir,"ACSMInput")
        self.accountdir = os.path.join(self.maindir,"account")
        if not os.path.exists(self.accountdir):
            raise Exception("Why does the account folder not exist?")
        
        # Default to the builtin account path
        self.deacsmprefs.defaults['path_to_account_data'] = self.accountdir

    
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

