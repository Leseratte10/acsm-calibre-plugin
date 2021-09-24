#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Calibre plugin for ACSM files.


# Revision history: 
# v0.0.1: First version.
# v0.0.2: Allow key extraction without extra binary call.


from calibre.customize import FileTypePlugin        # type: ignore
__version__ = '0.0.2'

PLUGIN_NAME = "DeACSM"
PLUGIN_VERSION_TUPLE = tuple([int(x) for x in __version__.split(".")])
PLUGIN_VERSION = ".".join([str(x)for x in PLUGIN_VERSION_TUPLE])

import os, shutil
import traceback
import subprocess

from calibre.utils.config import config_dir         # type: ignore
from calibre.constants import iswindows, isosx      # type: ignore
from calibre.gui2 import (question_dialog, error_dialog, info_dialog, choose_save_file)                     # type: ignore


# Test - need these:
import sys, os, zipfile, shutil, pwd, hashlib, base64, locale, urllib.request, datetime
from datetime import datetime, timedelta


from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from uuid import getnode
from lxml import etree



class DeACSM(FileTypePlugin):
    name                        = PLUGIN_NAME
    description                 = "Takes an Adobe ACSM file and converts that into a useable EPUB file. Python reimplementation of libgourou by Grégory Soutadé"
    supported_platforms         = ['linux']
    author                      = "Leseratte10"
    version                     = PLUGIN_VERSION_TUPLE
    minimum_calibre_version     = (5, 0, 0)
    file_types                  = set(['acsm'])
    on_import                   = True
    on_preprocess               = True
    priority                    = 2000

    def initialize(self):
        """
        On initialization, make sure we have all the libraries (python-rsa and cryptography)
        that we need.
        """

        try:
            self.pluginsdir = os.path.join(config_dir,"plugins")
            if not os.path.exists(self.pluginsdir):
                os.mkdir(self.pluginsdir)
            self.maindir = os.path.join(self.pluginsdir,"DeACSM")
            if not os.path.exists(self.maindir):
                os.mkdir(self.maindir)

            # Re-Extract modules

            self.moddir = os.path.join(self.maindir,"modules")
            if os.path.exists(self.moddir):
                shutil.rmtree(self.moddir, ignore_errors=True)
            
            os.mkdir(self.moddir)

            names = ["cryptography.zip", "rsa.zip"]
                
            lib_dict = self.load_resources(names)
            print("{0} v{1}: Copying needed library files from plugin zip".format(PLUGIN_NAME, PLUGIN_VERSION))

            for entry, data in lib_dict.items():
                file_path = os.path.join(self.moddir, entry)
                try:
                    os.remove(file_path)
                except:
                    pass

                try:
                    open(file_path,'wb').write(data)
                    with zipfile.ZipFile(file_path, 'r') as ref:
                        ref.extractall(self.moddir)
                    os.remove(file_path)

                except:
                    print("{0} v{1}: Exception when copying needed library files".format(PLUGIN_NAME, PLUGIN_VERSION))
                    traceback.print_exc()
                    pass

            try: 
                from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12module
            except: 
                sys.path.insert(0, os.path.join(self.moddir, "cryptography"))
                from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12module
                
            try: 
                import rsa
            except: 
                sys.path.insert(0, os.path.join(self.moddir, "rsa"))
                import rsa

        except Exception as e:
            traceback.print_exc()
            raise

        

            

    def is_customizable(self):
        return True

    def config_widget(self):
        import calibre_plugins.deacsm.config as config   # type: ignore
        return config.ConfigWidget(self.plugin_path)

    def save_settings(self, config_widget):
        config_widget.save_settings()

    def run(self, path_to_ebook: str):
        # This code gets called by Calibre with a path to the new book file. 
        # We need to check if it's an ACSM file

        print("{0} v{1}: Trying to parse file {2}".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.basename(path_to_ebook)))

        ext = os.path.splitext(path_to_ebook)[1].lower()

        if (ext != ".acsm"):
            print("{0} v{1}: That's not an ACSM, returning (is {2} instead)... ".format(PLUGIN_NAME, PLUGIN_VERSION, ext))
            return path_to_ebook

        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()

        print("{0} v{1}: Try to execute {2} ".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.join(self.verdir, "acsmdownloader")))

        outputname = self.temporary_file(".epub").name

        my_env = os.environ.copy()
        my_env["LD_LIBRARY_PATH"] = ".:" + my_env["LD_LIBRARY_PATH"]

        os.chmod(os.path.join(self.verdir, "acsmdownloader"), 0o775)

        ret = subprocess.run([os.path.join(self.verdir, "acsmdownloader"), "-d", os.path.join(deacsmprefs["path_to_account_data"], "device.xml"), 
        "-a", os.path.join(deacsmprefs["path_to_account_data"], "activation.xml"), 
        "-k", os.path.join(deacsmprefs["path_to_account_data"], "devicesalt"), 
        "-o", outputname, 
        "-v", "-v", 
        "-f", path_to_ebook ], capture_output=True, shell=False, cwd=self.verdir, env=my_env)

        print(ret)

        if not (os.path.exists(outputname)):
            error_dialog(None, "ACSM->EPUB failed", "Could not convert ACSM to EPUB:", det_msg=str(ret), show=True, show_copy_button=True)
            print("{0} v{1}: Failed, return original ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            return path_to_ebook

        if ("Parse PDF" in ret.stdout.decode("latin-1") or "Parse PDF" in ret.stderr.decode("latin-1")):
            # Looks like this is a PDF, move to PDF ...
            print("{0} v{1}: That's a PDF".format(PLUGIN_NAME, PLUGIN_VERSION))
            outputname2 = self.temporary_file(".pdf").name
            os.rename(outputname, outputname2)
            shutil.copy(outputname2, "/tmp/test.pdf")
            return outputname2



        return outputname
        

        


