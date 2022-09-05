#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GUI for the ACSM plugin. 
#

from calibre.customize import InterfaceActionBase        # type: ignore
from calibre.customize import PluginInstallationType



#@@CALIBRE_COMPAT_CODE@@

class DeACSMGUIExtension(InterfaceActionBase):
    name                        = "ACSM Input Plugin GUI Extension"
    description                 = "GUI code for ACSM Input Plugin (DeACSM). This is automatically installed and updated with the ACSM plugin."
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    minimum_calibre_version     = (4, 0, 0)

    can_be_disabled = False
    # This plugin will be auto-loaded from the ACSM Input plugin. It doesn't make sense for the user
    # to disable it. If necessary, the menu bar button can be removed through the Calibre settings.

    type = "File type"
    # Just so that the GUI extension shows up at the same place as the actual ACSM Input plugin.

    installation_type = PluginInstallationType.EXTERNAL
    # Mark this as user-installed so it shows up in the plugin list by default. 

    actual_plugin = "calibre_plugins.deacsm.gui_main:ActualDeACSMGUIExtension"

    def is_customizable(self):
        return False


