#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Migration plugin from "DeACSM" to "ACSM Input"
# See README.md for details.

import os, sys

from calibre.gui2.actions import InterfaceAction


class ActualMigrationPlugin(InterfaceAction):
    name                        = "DeACSM"



    def genesis(self): 
        print("DeACSM -> ACSM Input migration started ...")



        DOWNLOAD_URL = "https://github.com/Leseratte10/acsm-calibre-plugin/releases/download/config/TEST_calibre_plugin_acsminput_new_0_0_30.zip"
        

        # Okay, now download the new version and uninstall myself: 
        from calibre.utils.config import config_dir
        self.pluginsdir = os.path.join(config_dir,"plugins")
        if not os.path.exists(self.pluginsdir):
            os.mkdir(self.pluginsdir)

        new_path = os.path.join(self.pluginsdir, "ACSM Input.zip")

        if os.path.exists(new_path):
            # If so, delete ourselves and exit
            print("Already done ...")
            return

        if sys.version_info[0] == 2:
            import urllib
            urllib.urlretrieve(DOWNLOAD_URL, new_path)
        else:
            import urllib.request
            urllib.request.urlretrieve(DOWNLOAD_URL, new_path)

        # Check if the download was successful and the new file exists: 
        if os.path.exists(new_path):
            # Delete myself
            os.remove(os.path.join(self.pluginsdir, "DeACSM.zip"))

            # Forcibly add the new plugin
            from calibre.customize.ui import _config
            ui_plg_config = _config()
            plugins = ui_plg_config['plugins']
            plugins["ACSM Input"] = new_path
            ui_plg_config['plugins'] = plugins

            # Force-kill Calibre and have the user manually restart it:
            print("Force-exit, please restart")
            try: 
                os._exit(42)
            except TypeError: 
                os._exit()

        else: 
            print("Download / Update failed, trying again later ...")
            print("Please open a bug report for the ACSM Input plugin")



