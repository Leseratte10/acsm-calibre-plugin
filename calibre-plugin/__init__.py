#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Calibre plugin for ACSM files.


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

PLUGIN_NAME = "DeACSM"
PLUGIN_VERSION_TUPLE = (0, 0, 12)

from calibre.customize import FileTypePlugin        # type: ignore
__version__ = PLUGIN_VERSION = ".".join([str(x)for x in PLUGIN_VERSION_TUPLE])



from calibre.utils.config import config_dir         # type: ignore

import os, shutil, traceback, sys, time
import zipfile
from lxml import etree

class DeACSM(FileTypePlugin):
    name                        = PLUGIN_NAME
    description                 = "ACSM Input Plugin - Takes an Adobe ACSM file and converts that into a useable EPUB or PDF file. Python reimplementation of libgourou by Grégory Soutadé"
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    version                     = PLUGIN_VERSION_TUPLE
    minimum_calibre_version     = (5, 0, 0)
    file_types                  = set(['acsm'])
    on_import                   = True
    on_preprocess               = True
    priority                    = 2000

    def initialize(self):
        """
        On initialization, make sure we have all the libraries (python-rsa, cryptography, 
        oscrypto and their dependencies asn1crypto and pyasn1) that the plugin needs.
        Unfortunately the Adobe encryption is kinda weird and nonstandard and doesn't work
        with just the python modules included with Calibre. 
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
            self.maindir = os.path.join(self.pluginsdir,"DeACSM")
            if not os.path.exists(self.maindir):
                os.mkdir(self.maindir)

            # Re-Extract modules

            self.moddir = os.path.join(self.maindir,"modules")
            if os.path.exists(self.moddir):
                shutil.rmtree(self.moddir, ignore_errors=True)
            
            os.mkdir(self.moddir)

            names = ["cryptography.zip", "rsa.zip", "oscrypto.zip", "asn1crypto.zip", "pyasn1.zip"]
                
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

            sys.path.insert(0, os.path.join(self.moddir, "cryptography"))
            sys.path.insert(0, os.path.join(self.moddir, "rsa"))
            sys.path.insert(0, os.path.join(self.moddir, "oscrypto"))
            sys.path.insert(0, os.path.join(self.moddir, "asn1crypto"))
            sys.path.insert(0, os.path.join(self.moddir, "pyasn1"))
            
            # Okay, now all the modules are available, import the Adobe modules.

            # Account:
            try: 
                from calibre_plugins.deacsm.libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
                from calibre_plugins.deacsm.libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
            except: 
                from libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
                from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice

            # Fulfill:
            try: 
                from calibre_plugins.deacsm.libadobe import sendHTTPRequest
                from calibre_plugins.deacsm.libadobeFulfill import buildRights, fulfill
            except: 
                from libadobe import sendHTTPRequest
                from libadobeFulfill import buildRights, fulfill

            import calibre_plugins.deacsm.prefs as prefs     # type: ignore
            deacsmprefs = prefs.DeACSM_Prefs()
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
        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()

        activation_xml_path = os.path.join(deacsmprefs["path_to_account_data"], "activation.xml")

        container = None
        try: 
            container = etree.parse(activation_xml_path)
        except:
            return False

        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        

            if container.find(adeptNS("activationToken")) == None:
                return False

            if container.find(adeptNS("credentials")).find(adeptNS("pkcs12")) == None:
                return False

            return True
        except: 
            return False

    def download(self, replyData: str):


        try: 
            from calibre_plugins.deacsm.libadobe import sendHTTPRequest_DL2FILE
            from calibre_plugins.deacsm.libadobeFulfill import buildRights, fulfill
        except: 
            from libadobe import sendHTTPRequest_DL2FILE
            from libadobeFulfill import buildRights, fulfill

        try:
            from calibre_plugins.deacsm.libpdf import patch_drm_into_pdf
        except: 
            from libpdf import patch_drm_into_pdf


        adobe_fulfill_response = etree.fromstring(replyData)
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
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
            NSMAP = { "adept" : "http://ns.adobe.com/adept" }
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

    def run(self, path_to_ebook: str):
        # This code gets called by Calibre with a path to the new book file. 
        # We need to check if it's an ACSM file

        print("{0} v{1}: Trying to parse file {2}".format(PLUGIN_NAME, PLUGIN_VERSION, os.path.basename(path_to_ebook)))

        ext = os.path.splitext(path_to_ebook)[1].lower()

        if (ext != ".acsm"):
            print("{0} v{1}: That's not an ACSM, returning (is {2} instead)... ".format(PLUGIN_NAME, PLUGIN_VERSION, ext))
            return path_to_ebook

        # That's an ACSM.
        # We would fulfill this now, but first perform some sanity checks ...

        if not self.ADE_sanity_check(): 
            print("{0} v{1}: ADE auth is missing or broken ".format(PLUGIN_NAME, PLUGIN_VERSION))
            return path_to_ebook

        print("{0} v{1}: Try to fulfill ...".format(PLUGIN_NAME, PLUGIN_VERSION))

        try: 
            from calibre_plugins.deacsm.libadobe import sendHTTPRequest
            from calibre_plugins.deacsm.libadobeFulfill import buildRights, fulfill
        except: 
            from libadobe import sendHTTPRequest
            from libadobeFulfill import buildRights, fulfill

        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()


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
                    print("{0} v{1}: Error while executing other plugins".format(PLUGIN_NAME, PLUGIN_VERSION))
                    traceback.print_exc()
                    pass

                # Return path - either the original one or the one modified by the other plugins.
                return rpl


        return path_to_ebook
        

