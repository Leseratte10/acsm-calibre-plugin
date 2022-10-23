#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GUI for the ACSM plugin. 
#

from calibre.customize import InterfaceActionBase        # type: ignore
try: 
    from calibre.customize import PluginInstallationType
except:
    pass

from calibre_plugins.deacsm.__init__ import ACSMInput


#@@CALIBRE_COMPAT_CODE@@

class ACSMInputGUIExtension(InterfaceActionBase):
    name                        = "ACSM Input Plugin GUI Extension"
    description                 = "GUI code for ACSM Input Plugin. This is automatically installed and updated with the ACSM plugin."
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    minimum_calibre_version     = (4, 0, 0)

    can_be_disabled = False
    # This plugin will be auto-loaded from the ACSM Input plugin. It doesn't make sense for the user
    # to disable it. If necessary, the menu bar button can be removed through the Calibre settings.

    type = ACSMInput.type
    # Just so that the GUI extension shows up at the same place as the actual ACSM Input plugin.

    try: 
        installation_type = PluginInstallationType.EXTERNAL
        # Mark this as user-installed so it shows up in the plugin list by default. 
    except: 
        # Setting the Installation type doesn't always work on Calibre 4 and below.
        pass

    actual_plugin = "calibre_plugins.deacsm.gui_main:ActualACSMInputGUIExtension"

    def is_customizable(self):
        return False


