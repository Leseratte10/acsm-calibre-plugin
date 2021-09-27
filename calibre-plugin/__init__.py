#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Calibre plugin for ACSM files.


# Revision history: 
# v0.0.1: First version.
# v0.0.2: Allow key extraction without extra binary call (unreleased test version)
# v0.0.3: Standalone Calibre plugin for Linux, Windows, MacOS without the need for libgourou.
# v0.0.4: Manually execute DeDRM (if installed) after converting ACSM to EPUB.
# v0.0.5: Bugfix: DeDRM plugin was also executed if it's installed but disabled.


from calibre.customize import FileTypePlugin        # type: ignore
__version__ = '0.0.5'

PLUGIN_NAME = "DeACSM"
PLUGIN_VERSION_TUPLE = tuple([int(x) for x in __version__.split(".")])
PLUGIN_VERSION = ".".join([str(x)for x in PLUGIN_VERSION_TUPLE])


from calibre.utils.config import config_dir         # type: ignore

import os, shutil, traceback, sys
import zipfile
from lxml import etree

class DeACSM(FileTypePlugin):
    name                        = PLUGIN_NAME
    description                 = "Takes an Adobe ACSM file and converts that into a useable EPUB file. Python reimplementation of libgourou by Grégory Soutadé"
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
                try: 
                    from libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
                    from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
                except: 
                    print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
                    traceback.print_exc()

            # Fulfill:
            try: 
                from calibre_plugins.deacsm.libadobe import sendHTTPRequest
                from calibre_plugins.deacsm.libadobeFulfill import buildRights, fulfill
            except: 
                try: 
                    from libadobe import sendHTTPRequest
                    from libadobeFulfill import buildRights, fulfill
                except: 
                    print("{0} v{1}: Error while importing Fulfillment stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
                    traceback.print_exc()

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
            from calibre_plugins.deacsm.libadobe import sendHTTPRequest
            from calibre_plugins.deacsm.libadobeFulfill import buildRights, fulfill
        except: 
            try: 
                from libadobe import sendHTTPRequest
                from libadobeFulfill import buildRights, fulfill
            except: 
                print("{0} v{1}: Error while importing Fulfillment stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
                traceback.print_exc()


        adobe_fulfill_response = etree.fromstring(replyData)
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        adDC = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)


        download_url = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("src"))).text
        license_token_node = adobe_fulfill_response.find("./%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken")))

        rights_xml_str = buildRights(license_token_node)

        if (rights_xml_str is None):
            print("{0} v{1}: Building rights.xml failed!".format(PLUGIN_NAME, PLUGIN_VERSION))
            return None

        # Download eBook: 

        book_content = sendHTTPRequest(download_url)
        filetype = ".bin"
        
        if (book_content.startswith(b"PK")):
            print("That's a ZIP file -> EPUB")
            filetype = ".epub"
        elif (book_content.startswith(b"%PDF")):
            print("That's a PDF file")
            filetype = ".pdf"

        filename = self.temporary_file(filetype).name

        # Store book:
        f = open(filename, "wb")
        f.write(book_content)
        f.close()

        if filetype == ".epub":
            # Store EPUB rights / encryption stuff
            zf = zipfile.ZipFile(filename, "a")
            zf.writestr("META-INF/rights.xml", rights_xml_str)
            zf.close()
            print("{0} v{1}: File successfully fulfilled ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            return filename

        elif filetype == ".pdf":
            print("Successfully downloaded PDF, but PDF encryption is not yet supported")
            print("You will not be able to use the downloaded PDF file")
            print("Here's the raw string:")
            print(rights_xml_str)
            return None
        else: 
            print("Error: Weird filetype")
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
            try: 
                from libadobe import sendHTTPRequest
                from libadobeFulfill import buildRights, fulfill
            except: 
                print("{0} v{1}: Error while importing Fulfillment stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
                traceback.print_exc()


        success, replyData = fulfill(path_to_ebook)
        if (success is False):
            print("{0} v{1}: Hey, that didn't work: \n".format(PLUGIN_NAME, PLUGIN_VERSION) + replyData)
        else: 
            print("{0} v{1}: Downloading book ...".format(PLUGIN_NAME, PLUGIN_VERSION))
            rpl = self.download(replyData)
            if (rpl is not None):
                # Got a file

                # Because Calibre still thinks this is an ACSM file (not an EPUB)
                # it will not run other plugins like Alf / DeDRM. 
                # So we have to manually check if it's installed,
                # and if it is, run it to remove DRM.
                try: 
                    from calibre.customize.ui import _initialized_plugins, is_disabled
                    for plugin in _initialized_plugins:
                        if (plugin.name == "DeDRM" and not is_disabled(plugin)):
                            print("{0} v{1}: Executing DeDRM plugin ...".format(PLUGIN_NAME, PLUGIN_VERSION))
                            return plugin.run(rpl)
                except: 
                    print("{0} v{1}: Error while checking for DeDRM plugin.".format(PLUGIN_NAME, PLUGIN_VERSION))
                    pass

                # Looks like DeDRM is not installed, return book with DRM.
                return rpl


        return path_to_ebook
        

        


