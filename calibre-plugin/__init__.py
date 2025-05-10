#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Calibre plugin for ACSM files.

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
https://github.com/Leseratte10/acsm-calibre-plugin

ACSM Input Plugin for Calibre / acsm-calibre-plugin
Formerly known as "DeACSM"

This software is based on a Python reimplementation of the C++ library 
"libgourou" by Grégory Soutadé which is under the LGPLv3 or later 
license (http://indefero.soutade.fr/p/libgourou/).

I have no idea whether a reimplementation in another language counts 
as "derivative use", so just in case it does, I'm putting this project 
under the GPLv3 (which is allowed in the LGPLv3 license) to prevent any 
licensing issues. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

See the "LICENSE" file for a full copy of the GNU GPL v3.

'''

# Revision history: 
# v0.0.1: First version.
# v0.0.2: Allow key extraction without extra binary call (unreleased test version)
# v0.0.3: Standalone Calibre plugin for Linux, Windows, MacOS without the need for libgourou.
# v0.0.4: Manually execute DeDRM (if installed) after converting ACSM to EPUB.
# v0.0.5: Bugfix: DeDRM plugin was also executed if it's installed but disabled.
# v0.0.6: First PDF support, allow importing previously exported activation data.
# v0.0.7: More PDF logging, PDF reading in latin-1, MacOS locale bugfix
# v0.0.8: More PDF bugfixes, support unlimited PDF file sizes, tell Calibre ACSMs are books.
# v0.0.9: Add FulfillmentNotification support, add LoanReturn support.
# v0.0.10: Fix nonce calculation, merge PRs #3 and #4 (PyCryptodome stuff)
# v0.0.11: Ignore SSL errors during ACS notify, improve element hashing code, 
#          improve PassHash support, include UUID in key export filename, 
#          fix bug that would block other FileTypePlugins
# v0.0.12: Fix Calibre Plugin index / updater
# v0.0.13: v0.0.13 was a development / beta version with lots of different published test 
#          versions. To make support easier there's no "final" v0.0.13 version. Instead, 
#          all the changes from the various v0.0.13 beta versions are released with v0.0.14. 
# v0.0.14: Add support for emulating multiple ADE versions (1.7.2, 2.0.1, 3.0.1, 4.0.3, 4.5.11),
#          add code to import existing activation from ADE (Windows, MacOS or Linux/Wine), 
#          add code to remove an existing activation from the plugin (Ctrl+Shift+D),
#          fix race condition when importing multiple ACSMs simultaneously, 
#          fix authorization failing with certain non-ASCII characters in username, 
#          add detailed logging toggle setting, add auto-delete ACSM setting, 
#          add useful error message for ACSMs with nonstandard download type.
# v0.0.15: Add support for anonymous authorizations, add support for other ID providers, 
#          fix ACSM files from Google Play books (no metadata node), 
#          allow converting an anonymous auth to an AdobeID auth, 
#          update python-cryptography from 3.4.8 to 36.0.1, update python-rsa from 4.7.2 to 4.8.
# v0.0.16: Ignore fatal HTTP errors and/or a missing or broken server during optional 
#          fulfillment notifications, allow authorizing an eReader through USB (experimental), 
#          drop dependencies python-cryptography, python-rsa and python-pyasn1. 
#          add a ton of testing code, try to prevent AV false-positives, 
#          experimental support for Python2 / Calibre < 5, 
#          fix broken URLs with missing protocol, fix loan data for loans without device ID, 
#          fix nonce calculation yet again, merge #26 to make importing a WINE auth more reliable,
#          update python-oscrypto to unofficial fork to fix OpenSSL 3 support.
# v0.0.17: 
#          Fix bug that would sometimes return the wrong book (or none at all) if you had 
#          multiple active loans from the same distributor, add experimental GUI button, 
#          rename plugin from "DeACSM" to "ACSM Input". BETA build, not a normal release!!
#
# v0.1.0:  Continue work on renaming from "DeACSM" to "ACSM Input". 
#          The big version number jump is to make that name change clearer,
#          and to support the "migration plugin" to rename the plugin.
#          Print useful warning if LicenseServiceCertificate download fails,
#          fix error with the loan list not being updated when importing multiple ACSMs at once,
#          fix bug with the GUI extension in non-English environments,
#          fix softlock when importing a large number of ACSM files at once,
#          fix "account folder not found" error message on some clean installations,
#          add experimental support for Calibre 3.48. 




PLUGIN_NAME = "ACSM Input"
PLUGIN_VERSION_TUPLE = (0, 1, 0)

from calibre.customize import FileTypePlugin        # type: ignore
__version__ = PLUGIN_VERSION = ".".join([str(x)for x in PLUGIN_VERSION_TUPLE])



from calibre.utils.config import config_dir         # type: ignore
from calibre.utils.lock import singleinstance       # type: ignore

try:
    from calibre.utils.lock import SingleInstance       # type: ignore
except:
    from calibre_plugins.deacsm.singleinstance_helper import SingleInstance

import os, shutil, traceback, sys, time, io, random
import zipfile
from lxml import etree

#@@CALIBRE_COMPAT_CODE@@

class ACSMInput(FileTypePlugin):
    name                        = PLUGIN_NAME
    description                 = "Takes an Adobe ACSM file and converts that into a useable EPUB or PDF file. Formerly known as DeACSM. Based on the libgourou library by Grégory Soutadé"
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    version                     = PLUGIN_VERSION_TUPLE
    minimum_calibre_version     = (3, 48, 0)
    file_types                  = set(['acsm'])
    on_import                   = True
    on_preprocess               = True
    priority                    = 2000

    def init_embedded_plugins(self):
        """
        A Calibre plugin can normally only contain one Plugin class. 
        In our case, this would be the file type class. 
        However, we want to load the GUI plugin, too, so we have to trick
        Calibre into believing that there's actually a 2nd plugin.
        """
        from calibre.customize.ui import _initialized_plugins
        from calibre_plugins.deacsm.gui_main_wrapper import ACSMInputGUIExtension

        def init_plg(plg_type):
            for plugin in _initialized_plugins:
                if isinstance(plugin, plg_type):
                    return plugin
            
            plg_type.version = self.version
            plg_type.minimum_calibre_version = self.minimum_calibre_version
            plugin = plg_type(self.plugin_path)
            _initialized_plugins.append(plugin)
            plugin.initialize()

            return plugin

        init_plg(ACSMInputGUIExtension)



    def initialize(self):

        """
        On initialization, make sure we have all the libraries (oscrypto and its dependency 
        asn1crypto) that the plugin needs. Unfortunately the Adobe encryption is kinda weird 
        and nonstandard and doesn't work with just the python modules included with Calibre. 
        """

        try:

            # Patch Calibre to consider "ACSM" a book. This makes ACSM files show up
            # in the "Add Book" file selection, and it also makes the auto-add feature useable.
            try: 
                from calibre.ebooks import BOOK_EXTENSIONS
                if ("acsm" not in BOOK_EXTENSIONS):
                    BOOK_EXTENSIONS.append("acsm")
            except:
                print("{0} v{1}: Couldn't add ACSM to book extension list:".format(PLUGIN_NAME, PLUGIN_VERSION))
                traceback.print_exc()


            self.pluginsdir = os.path.join(config_dir,"plugins")
            if not os.path.exists(self.pluginsdir):
                os.mkdir(self.pluginsdir)

            
            if singleinstance("__acsm_rename_old_plugin"):
                # If the old DeACSM plugin still exists, rename it to BAK or something so it doesn't load.
                if os.path.exists(os.path.join(self.pluginsdir, "DeACSM.zip")):
                    os.rename(os.path.join(self.pluginsdir, "DeACSM.zip"), os.path.join(self.pluginsdir, "DeACSM.BAK"))
                    
            
            try: 
                # Make sure the GUI extension is loaded:
                self.init_embedded_plugins()    
            except: 
                # Apparently this can fail - if it does, ignore errors so the rest of the plugin still works.
                print("{0} v{1}: Couldn't initialize GUI plugin:".format(PLUGIN_NAME, PLUGIN_VERSION))
                traceback.print_exc()
                pass
                
            self.maindir_old = os.path.join(self.pluginsdir,"DeACSM")
            self.maindir = os.path.join(self.pluginsdir,"ACSMInput")

            # Do NOT try to migrate data, that just screws everything up. 
            # If this is a fresh install of the plugin and there's no old data, 
            # use the new path. Otherwise, if there's already data at the old location,
            # continue to use that.

            if os.path.exists(self.maindir_old):
                # We have the old folder, continue to use that
                self.maindir = self.maindir_old


            if not os.path.exists(self.maindir):
                os.mkdir(self.maindir)

            # Extract new modules

            self.moddir = os.path.join(self.maindir,"modules")
            if not os.path.exists(self.moddir):
                os.mkdir(self.moddir)

            # Check if we have a module id:
            # Modules will only be extracted if this has changed. 
            # This A) saves time because we don't extract every time, 
            # and B) prevents a race condition.
            # The compiling scripts need to be adapted to modify 
            # the module_id.txt in the plugin ZIP every time the 
            # modules change

            try: 
                ts_file = os.path.join(self.moddir, "module_id.txt")
                f = open(ts_file, "r")
                id = f.readline().strip()
                f.close()
            except: 
                # No timestamp found, probably upgrading from an older version.
                id = None

            # Check ID file in the plugin ZIP
            try: 
                ts_dict = self.load_resources( ["module_id.txt"] )
                id_plugin = ts_dict["module_id.txt"].decode("latin-1").split('\n')[0].strip()
            except: 
                # No timestamp found in the plugin ZIP?
                # Assume that I made a mistake bundling the plugin, extract anyways.
                id_plugin = None

            if id is None or id_plugin is None or id != id_plugin:
                print("Module update from \"{0}\" to \"{1}\", extracting ...".format(id, id_plugin))
                # Something changed, extract modules.

                if not singleinstance("__acsm_extracting modules"):
                    print("Skipping because another instance is already doing that.")
                else:
                    if os.path.exists(self.moddir):
                        shutil.rmtree(self.moddir, ignore_errors=True)

                    os.mkdir(self.moddir)

                    names = ["oscrypto.zip", "asn1crypto.zip"]

                    # oscrypto is needed to parse the pkcs12 data from Adobe.
                    # asn1crypto is a dependency of oscrypto.
                        
                    lib_dict = self.load_resources(names)

                    for entry, data in lib_dict.items():
                        try:
                            with zipfile.ZipFile(io.BytesIO(data), 'r') as ref:
                                ref.extractall(self.moddir)

                        except:
                            print("{0} v{1}: Exception when copying needed library files".format(PLUGIN_NAME, PLUGIN_VERSION))
                            traceback.print_exc()
                            pass           


                    # Write module ID
                    if id_plugin is not None: 
                        mod_file = os.path.join(self.moddir, "module_id.txt")
                        f = open(mod_file, "w")
                        f.write(id_plugin)
                        f.close()


            sys.path.insert(0, os.path.join(self.moddir, "oscrypto"))
            sys.path.insert(0, os.path.join(self.moddir, "asn1crypto"))
            
            # Okay, now all the modules are available, import the Adobe modules.

            
            # On some systems, like NixOS, the path to libcrypto and libssl 
            # isn't autodetected correctly. To fix this, allow overriding
            # these paths using environment variables.
            # Crucial to import first, as libadobe imports oscrypto as well

            libcrypto_path = os.getenv("ACSM_LIBCRYPTO", None)
            libssl_path = os.getenv("ACSM_LIBSSL", None)

            import platform
            if platform.system() == "Darwin":
                # if MacOS and running in a terminal, the environment variables
                # set by a LaunchAgent .plist file are not available in the
                # same way as they are when launched by the GUI.
                if libcrypto_path is None:
                    libcrypto_path = self.get_launchctl_env("ACSM_LIBCRYPTO")
                if libssl_path is None:
                    libssl_path = self.get_launchctl_env("ACSM_LIBSSL")

            if (
                libcrypto_path
                and libssl_path
                and (
                    (os.path.exists(libcrypto_path) and os.path.exists(libssl_path))
                    or platform.system() == "Darwin"
                )
            ):
                # Use paths if set, but files may not exist on MacOS (may be
                # in the dyld shared cache)
                print(
                    "{0} v{1}: Using environment-specified crypto libraries {2} {3}".format(
                        PLUGIN_NAME, PLUGIN_VERSION, libcrypto_path, libssl_path
                    )
                )
            elif platform.system() == "Darwin" and self.check_homebrew_openssl():
                # MacOS with Homebrew must specify Apple signed libraries instead
                libcrypto_path, libssl_path = self.get_mac_crypto_libs()

            if libcrypto_path is not None and libssl_path is not None:
                if (
                    os.path.exists(libcrypto_path) and os.path.exists(libssl_path)
                ) or platform.system() == "Darwin":
                    import oscrypto     # type: ignore

                    oscrypto.use_openssl(
                        libcrypto_path = libcrypto_path,
                        libssl_path = libssl_path,
                    )


            from libadobe import createDeviceKeyFile, update_account_path, sendHTTPRequest
            from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
            from libadobeFulfill import buildRights, fulfill


            import calibre_plugins.deacsm.prefs as prefs     # type: ignore
            deacsmprefs = prefs.ACSMInput_Prefs()
            update_account_path(deacsmprefs["path_to_account_data"])

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

    def ADE_sanity_check(self):
        from libadobe import get_activation_xml_path

        container = None
        try: 
            container = etree.parse(get_activation_xml_path())
        except:
            print("ADE sanity check: Can't parse activation container")
            return False

        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        

            if container.find(adeptNS("activationToken")) == None:
                print("ADE sanity check: activationToken missing")
                return False

            if container.find(adeptNS("credentials")).find(adeptNS("pkcs12")) == None:
                print("ADE sanity check: pkcs12 missing")
                return False

            try:  
                from libadobeFulfill import getDecryptedCert
                if getDecryptedCert() is None:
                    print("ADE sanity check: Can't decrypt pkcs12")
                    return False
            except: 
                print("Skipping decryption check")

            return True
        except: 
            print("ADE sanity check: Exception")
            traceback.print_exc()
            return False

    def download(self, replyData):
        # type: (str) -> str


        from libadobe import sendHTTPRequest_DL2FILE
        from libadobeFulfill import buildRights, fulfill
        from libpdf import patch_drm_into_pdf


        adobe_fulfill_response = etree.fromstring(replyData)
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        
        try: 
            download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
        except: 
            print("{0} v{1}: FulfillmentResult does not contain the <src> tag. This may be an ACSM with download type 'auth'?".format(PLUGIN_NAME, PLUGIN_VERSION))
            print("{0} v{1}: Please download the book through ADE (so the ACSM file is 'used').".format(PLUGIN_NAME, PLUGIN_VERSION))
            print("{0} v{1}: After that, please open a bug report and attach the ACSM file.".format(PLUGIN_NAME, PLUGIN_VERSION))
            return None

        license_token_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))

        rights_xml_str = buildRights(license_token_node)

        if (rights_xml_str is None):
            print("{0} v{1}: Building rights.xml failed!".format(PLUGIN_NAME, PLUGIN_VERSION))
            return None

        # Download eBook: 
        print("{0} v{1}: Loading book from {2}".format(PLUGIN_NAME, PLUGIN_VERSION, download_url))

        filename_tmp = self.temporary_file(".blob").name

        dl_start_time = int(time.time() * 1000)
        ret = sendHTTPRequest_DL2FILE(download_url, filename_tmp)
        dl_end_time = int(time.time() * 1000)

        print("Download took %d ms (HTTP %d)" % (dl_end_time - dl_start_time, ret))

        if (ret != 200):
            print("{0} v{1}: Download failed with error {2}".format(PLUGIN_NAME, PLUGIN_VERSION, ret))
            return None            

        filetype = ".bin"

        book_content = None

        with open(filename_tmp, "rb") as f:
            book_content = f.read(10)
                
        if (book_content.startswith(b"PK")):
            print("That's a ZIP file -> EPUB")
            filetype = ".epub"
        elif (book_content.startswith(b"%PDF")):
            print("That's a PDF file")
            filetype = ".pdf"

        filename = self.temporary_file(filetype).name

        # Move to file name with matching extension
        shutil.move(filename_tmp, filename)


        if filetype == ".epub":
            # Store EPUB rights / encryption stuff
            zf = zipfile.ZipFile(filename, "a")
            zf.writestr("META-INF/rights.xml", rights_xml_str)
            zf.close()
            print("{0} v{1}: File successfully fulfilled ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            return filename

        elif filetype == ".pdf":
            adobe_fulfill_response = etree.fromstring(rights_xml_str)

            adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
            resource = adobe_fulfill_response.find("./%s/%s" % (adNS("licenseToken"), adNS("resource"))).text

            print("{0} v{1}: Downloaded PDF, adding encryption config ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            pdf_tmp_file = self.temporary_file(filetype).name
            ret = patch_drm_into_pdf(filename, rights_xml_str, pdf_tmp_file, resource)
            if (ret):
                print("{0} v{1}: File successfully fulfilled ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            else:
                print("{0} v{1}: There was an error patching the PDF file.".format(PLUGIN_NAME, PLUGIN_VERSION))

            return pdf_tmp_file
        else: 
            print("{0} v{1}: Error: Unsupported file type ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            return None

    def run(self, path_to_ebook):
        # type: (str) -> str


        # This code gets called by Calibre with a path to the new book file. 

        # Make sure there's only a single instance of this function running ever. 
        # Calibre loves to run these in parallel when many ACSM files are being imported.
        # However that A) messes with the loan records written to a file, and B) that behaviour
        # is significantly different from ADE so Adobe could use that to detect this plugin. 
        
        # So, we're trying to use Calibre's singleinstance feature to prevent that. 


        counter = 0
        thread_id = -1

        try: 
            import threading
            thread_id = threading.current_thread().ident
        except:
            pass

        while True:
            with SingleInstance("__acsm_plugin_execute_run_acsm_file") as si:
                if si:
                    return self.run_single(path_to_ebook)
                else:
                    counter += 1
                    if (counter % 100 == 0):
                        print("Thread {0} still waiting for lock, attempt {1}".format(thread_id, counter))
                    time.sleep(0.1)



    def run_single(self, path_to_ebook):
        # type: (str) -> str
        try: 

            # We need to check if it's an ACSM file

            import calibre_plugins.deacsm.prefs as prefs     # type: ignore
            deacsmprefs = prefs.ACSMInput_Prefs()

            print("{0} v{1}: Trying to parse file {2}".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.basename(path_to_ebook)))

            ext = os.path.splitext(path_to_ebook)[1].lower()

            if (ext != ".acsm"):
                print("{0} v{1}: That's not an ACSM, returning (is {2} instead)... ".format(PLUGIN_NAME, PLUGIN_VERSION, ext))
                return path_to_ebook

            # We would fulfill this now, but first perform some sanity checks ...

            if not self.ADE_sanity_check(): 
                print("{0} v{1}: ADE auth is missing or broken ".format(PLUGIN_NAME, PLUGIN_VERSION))
                return path_to_ebook


            from libadobe import are_ade_version_lists_valid
            from libadobeFulfill import fulfill

            if not are_ade_version_lists_valid():
                print("{0} v{1}: ADE version list mismatch, please open a bug report.".format(PLUGIN_NAME, PLUGIN_VERSION))
                return path_to_ebook

            print("{0} v{1}: Try to fulfill ...".format(PLUGIN_NAME, PLUGIN_VERSION))

            success, replyData = fulfill(path_to_ebook, deacsmprefs["notify_fulfillment"])

            if (success is False):
                print("{0} v{1}: Hey, that didn't work: \n".format(PLUGIN_NAME, PLUGIN_VERSION) + replyData)
            else: 
                print("{0} v{1}: Downloading book ...".format(PLUGIN_NAME, PLUGIN_VERSION))
                rpl = self.download(replyData)
                if (rpl is not None):
                    # Got a file

                    # Because Calibre still thinks this is an ACSM file (not an EPUB)
                    # it will not run other FileTypePlugins that handle EPUB (or PDF) files.
                    # Loop through all plugins (the list is already sorted by priority), 
                    # then execute all of them that can handle EPUB / PDF.

                    # if the source file is supposed to be deleted after successful fulfillment,
                    # this is set to True
                    # If there's any errors whatsoever during export / plugin execution,
                    # this will be set back to False to prevent deletion.
                    delete_src_file = deacsmprefs["delete_acsm_after_fulfill"]

                    try: 
                        from calibre.customize.ui import _initialized_plugins, is_disabled
                        from calibre.customize import FileTypePlugin

                        original_file_for_plugins = rpl

                        oo, oe = sys.stdout, sys.stderr

                        for plugin in _initialized_plugins:

                            #print("{0} v{1}: Plugin '{2}' has prio {3}".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name, plugin.priority))

                            # Check if this is a FileTypePlugin
                            if not isinstance(plugin, FileTypePlugin):
                                #print("{0} v{1}: Plugin '{2}' is no FileTypePlugin, skipping ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name))
                                continue

                            # Check if it's disabled
                            if is_disabled(plugin):
                                #print("{0} v{1}: Plugin '{2}' is disabled, skipping ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name))
                                continue

                            if plugin.name == self.name:
                                #print("{0} v{1}: Plugin '{2}' is me - skipping".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name))
                                continue

                            # Check if it's supposed to run on import:
                            if not plugin.on_import:
                                #print("{0} v{1}: Plugin '{2}' isn't supposed to run during import, skipping ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name))
                                continue

                            # Check filetype
                            # If neither the book file extension nor "*" is in the plugin,
                            # don't execute it.
                            my_file_type = os.path.splitext(rpl)[-1].lower().replace('.', '')
                            if (not my_file_type in plugin.file_types):
                                #print("{0} v{1}: Plugin '{2}' doesn't support {3} files, skipping ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name, my_file_type))
                                continue

                            if ("acsm" in plugin.file_types or "*" in plugin.file_types):
                                #print("{0} v{1}: Plugin '{2}' would run anyways, skipping ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name, my_file_type))
                                continue

                            print("{0} v{1}: Executing plugin {2} ...".format(PLUGIN_NAME, PLUGIN_VERSION, plugin.name))

                            plugin.original_path_to_file = original_file_for_plugins

                            try: 
                                plugin_ret = None
                                plugin_ret = plugin.run(rpl)
                            except: 
                                delete_src_file = False
                                print("{0} v{1}: Running file type plugin failed with traceback:".format(PLUGIN_NAME, PLUGIN_VERSION))
                                traceback.print_exc(file=oe)

                            # Restore stdout and stderr, in case a plugin broke them.
                            sys.stdout, sys.stderr = oo, oe


                            if plugin_ret is not None:
                                # If the plugin returned a new path, update that.
                                print("{0} v{1}: Plugin returned path '{2}', updating.".format(PLUGIN_NAME, PLUGIN_VERSION, plugin_ret))
                                rpl = plugin_ret
                            else: 
                                print("{0} v{1}: Plugin returned nothing - skipping".format(PLUGIN_NAME, PLUGIN_VERSION))

                                

                    except: 
                        delete_src_file = False
                        print("{0} v{1}: Error while executing other plugins".format(PLUGIN_NAME, PLUGIN_VERSION))
                        traceback.print_exc()
                        pass

                    # If enabled, and if we didn't encounter any errors, delete the source ACSM file.
                    if delete_src_file:
                        try: 
                            if os.path.exists(path_to_ebook):
                                print("{0} v{1}: Deleting existing ACSM file {2} ...".format(PLUGIN_NAME, PLUGIN_VERSION, path_to_ebook))
                                os.remove(path_to_ebook)
                        except: 
                            print("{0} v{1}: Failed to delete source ACSM after fulfillment.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    
                    
                    # Return path - either the original one or the one modified by the other plugins.
                    return rpl

            return path_to_ebook
        except: 
            traceback.print_exc()
            return path_to_ebook
        
    def check_homebrew_openssl(self):
        """Check if Homebrew's OpenSSL is linked and might cause issues"""
        import platform
        import os

        if platform.system() != "Darwin":
            return False

        brew_openssl_link = "/usr/local/lib/libcrypto.dylib"
        if os.path.exists(brew_openssl_link) and os.path.islink(brew_openssl_link):
            link_target = os.readlink(brew_openssl_link)
            if "openssl@3" in link_target:
                return True
        return False


    def test_libs(self,l_crypto, l_ssl):
        self.wipe_crypto()  # because might not have restarted calibre
        try:
            if l_crypto is not None and l_ssl is not None:
                # if None args, we are trying to load the default (homebrew) libraries
                import oscrypto  # type: ignore

                oscrypto.use_openssl(
                    libcrypto_path=l_crypto,
                    libssl_path=l_ssl,
                )

            from libadobe import createDeviceKeyFile

            # print(
            #    "{0} v{1}: successful load for {2} {3}".format(
            #        PLUGIN_NAME, PLUGIN_VERSION, l_crypto, l_ssl
            #    )
            # )
            return True
        except Exception as e:
            print(
                "{0} v{1}: failed to load {2} {3} error: {4}".format(
                    PLUGIN_NAME, PLUGIN_VERSION, l_crypto, l_ssl, str(e)
                )
            )
            self.wipe_crypto()  # because bad load
            return False


    def wipe_crypto(self):
        # Aggressively clear all oscrypto and libadobe modules
        for name in list(sys.modules.keys()):
            if (
                name == "oscrypto"
                or name.startswith("oscrypto.")
                or name == "asn1crypto"
                or name.startswith("asn1crypto.")
                or name == "libadobe"
                or name.startswith("libadobe.")
                or name == "libadobeAccount"
                or name.startswith("libadobeAccount.")
                or name == "libadobeFulfill"
                or name.startswith("libadobeFulfill.")
            ):
                try:
                    del sys.modules[name]
                    # debug_log(f"Deleted module: {name}")
                except:
                    pass

        # Explicitly delete all functions imported from libadobe modules
        try:
            del createDeviceKeyFile
            del update_account_path
            del sendHTTPRequest
            del createDeviceFile
            del createUser
            del signIn
            del activateDevice
            del buildRights
            del fulfill
            del getDecryptedCert
            del are_ade_version_lists_valid
            del get_activation_xml_path
            del sendHTTPRequest_DL2FILE
        except:
            pass


    def get_mac_crypto_libs(self):
        # if on MacOS and homebrew is installed, its openssl library will
        # not work because it is not signed, but that is what libadobe
        # will load by default.
        #
        # MacOS finds specific signed libraries in its 'dyld shared cache', but
        # attempting to load a generic lib like "/usr/lib/libssl.dylib" will HARD
        # crash calibre with error "Invalid dylib load. Clients should not load
        # the unversioned libcrypto dylib as it does not have a stable ABI."
        #
        # N.B. the files in the dyld shared cache do not exist in the file system
        # so do not test path.exists().

        libs_loaded = False

        # this is tried for every acsm file load, so skip the test failing
        # as the homebrew libraries are unlikely to be signed for some time
        # if not libs_loaded:
        #    # try the default (homebrew) libraries, maybe they are signed in the future
        #    libcrypto_path = None
        #    libssl_path = None
        #    libs_loaded = test_libs(libcrypto_path, libssl_path)
        if not libs_loaded:
            # this version has been present since ca. 2020
            libcrypto_path = "/usr/lib/libcrypto.46.dylib"
            libssl_path = "/usr/lib/libssl.46.dylib"
            libs_loaded = self.test_libs(libcrypto_path, libssl_path)
        if not libs_loaded:
            # this version has been present since ca. 2015
            libcrypto_path = "/usr/lib/libcrypto.35.dylib"
            libssl_path = "/usr/lib/libssl.35.dylib"
            libs_loaded = self.test_libs(libcrypto_path, libssl_path)

        if not libs_loaded:
            print(
                "{0} v{1}: Unable to find Mac crypto/ssl libraries that work".format(
                    PLUGIN_NAME, PLUGIN_VERSION
                )
            )
            print("{0} v{1}: Try 'brew unlink openssl'".format(PLUGIN_NAME, PLUGIN_VERSION))

        return libcrypto_path, libssl_path


    def get_launchctl_env(self, var_name):
        import subprocess

        try:
            result = subprocess.run(
                ["launchctl", "getenv", var_name], capture_output=True, text=True
            )
            value = result.stdout.strip()
            return value if value else None
        except Exception:
            return None

