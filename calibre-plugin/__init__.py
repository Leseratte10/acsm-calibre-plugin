#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Calibre plugin for ACSM files.

'''
Copyright (c) 2021-2026 Leseratte10
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


PLUGIN_NAME = "ACSM Input"
PLUGIN_VERSION_TUPLE = (0, 1, 0)

from calibre.customize import FileTypePlugin        # type: ignore
__version__ = PLUGIN_VERSION = ".".join([str(x)for x in PLUGIN_VERSION_TUPLE])


from calibre.utils.config import config_dir         # type: ignore
from calibre.utils.lock import singleinstance       # type: ignore

try:
    from calibre.utils.lock import SingleInstance       # type: ignore
except:
    from .singleinstance_helper import SingleInstance

import os, shutil, traceback, sys, time
import zipfile
from lxml import etree

class ACSMInput(FileTypePlugin):
    name                        = PLUGIN_NAME
    description                 = "Takes an Adobe / ByteBooks ACSM file and converts that into a useable EPUB or PDF file. Formerly known as DeACSM."
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
        from calibre.customize.ui import _initialized_plugins       # type: ignore
        from .gui_main_wrapper import ACSMInputGUIExtension

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

        try:

            # Patch Calibre to consider "ACSM" a book. This makes ACSM files show up
            # in the "Add Book" file selection, and it also makes the auto-add feature useable.
            try: 
                from calibre.ebooks import BOOK_EXTENSIONS  # type: ignore
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
                
            self.maindir = os.path.join(self.pluginsdir,"ACSMInput")

            if not os.path.exists(self.maindir):
                os.mkdir(self.maindir)

            
            # The module folder is no longer needed, so delete it if it is present. 
            self.moddir = os.path.join(self.maindir,"modules")
            if os.path.exists(self.moddir):
                shutil.rmtree(self.moddir, ignore_errors=True)

            

            from .libadobe import update_account_path
            from .libadobeAccount import changeDeviceVersion


            from . import prefs
            acsmprefs = prefs.ACSMInput_Prefs()
            update_account_path(acsmprefs["path_to_account_data"])
            # This is needed to correctly update to an emulated ByteBooks Digital Edition 5.0 for older activations.
            try: 
                changeDeviceVersion(0, onlyIfUnknown=True)
            except TypeError:
                #print("Type error, this can happen during an update from an older version.")
                pass

        except Exception as e:
            traceback.print_exc()
            raise
            

    def is_customizable(self):
        return True

    def config_widget(self):
        from . import config
        return config.ConfigWidget(self.plugin_path)

    def save_settings(self, config_widget):
        config_widget.save_settings()

    def ADE_sanity_check(self):
        from .libadobe import get_activation_xml_path

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
                from .libadobeFulfill import getDecryptedCert
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


        from .libadobe import sendHTTPRequest_DL2FILE
        from .libadobeFulfill import buildRights
        from .libpdf import patch_drm_into_pdf


        adobe_fulfill_response = etree.fromstring(replyData)
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        
        try: 
            download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
        except: 
            # If src is present, it is used. If it isn't, ADE uses /Download instead.
            # If downloadType is "simple", it does a GET. If it's anything else, it does a POST including a bunch of data.
            print("{0} v{1}: FulfillmentResult does not contain the <src> tag. This may be an ACSM with download type 'auth'?".format(PLUGIN_NAME, PLUGIN_VERSION))
            print("{0} v{1}: Please go into the plugin settings, make sure 'Enable verbose debug logging' is enabled, then try again.".format(PLUGIN_NAME, PLUGIN_VERSION))
            print("{0} v{1}: After that, please open a bug report and attach the full log file.".format(PLUGIN_NAME, PLUGIN_VERSION))
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
        ret = sendHTTPRequest_DL2FILE(download_url, filename_tmp, False)
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
                return pdf_tmp_file
            else:
                print("{0} v{1}: There was an error patching the PDF file.".format(PLUGIN_NAME, PLUGIN_VERSION))
                return None

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

            from . import prefs
            acsmprefs = prefs.ACSMInput_Prefs()

            print("{0} v{1}: Trying to parse file {2}".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.basename(path_to_ebook)))

            ext = os.path.splitext(path_to_ebook)[1].lower()

            if (ext != ".acsm"):
                print("{0} v{1}: That's not an ACSM, returning (is {2} instead)... ".format(PLUGIN_NAME, PLUGIN_VERSION, ext))
                return path_to_ebook

            # We would fulfill this now, but first perform some sanity checks ...

            if not self.ADE_sanity_check(): 
                print("{0} v{1}: ADE auth is missing or broken ".format(PLUGIN_NAME, PLUGIN_VERSION))
                return path_to_ebook


            from .libadobe import are_ade_version_lists_valid
            from .libadobeFulfill import fulfill

            if not are_ade_version_lists_valid():
                print("{0} v{1}: ADE version list mismatch, please open a bug report.".format(PLUGIN_NAME, PLUGIN_VERSION))
                return path_to_ebook

            print("{0} v{1}: Try to fulfill ...".format(PLUGIN_NAME, PLUGIN_VERSION))

            success, replyData = fulfill(path_to_ebook, acsmprefs["notify_fulfillment"])

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
                    delete_src_file = acsmprefs["delete_acsm_after_fulfill"]

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
        

