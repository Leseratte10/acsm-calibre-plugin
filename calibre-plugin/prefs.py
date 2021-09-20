#!/usr/bin/env python3
# -*- coding: utf-8 -*-



# Standard Python modules.
import os
import traceback

from calibre.utils.config import JSONConfig, config_dir  # type: ignore
from calibre_plugins.deacsm.__init__ import PLUGIN_NAME  # type: ignore


class DeACSM_Prefs():
    def __init__(self):
        JSON_PATH = os.path.join("plugins", PLUGIN_NAME.strip().lower().replace(' ', '_') + '.json')
        self.deacsmprefs = JSONConfig(JSON_PATH)

        self.deacsmprefs.defaults['configured'] = False

        self.pluginsdir = os.path.join(config_dir,"plugins")
        if not os.path.exists(self.pluginsdir):
            os.mkdir(self.pluginsdir)
        self.maindir = os.path.join(self.pluginsdir,"DeACSM")
        if not os.path.exists(self.maindir):
            os.mkdir(self.maindir)
        self.accountdir = os.path.join(self.maindir,"account")
        if not os.path.exists(self.accountdir):
            os.mkdir(self.accountdir)
        
        # Default to the builtin UA
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

