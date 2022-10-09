#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Migration plugin from "DeACSM" to "ACSM Input"
# See README.md for details.


# Revision history: 
# v0.0.20: First version of the migration plugin, released under the old name.


from calibre.customize import InterfaceActionBase        # type: ignore
try: 
    from calibre.customize import PluginInstallationType
except:
    pass


class DeACSMMigrationPlugin(InterfaceActionBase):
    name                        = "DeACSM"
    description                 = "Extension for the ACSM Input plugin to migrate to a new plugin name"
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    minimum_calibre_version     = (4, 0, 0)
    version                     = (0, 0, 20)

    can_be_disabled = False
    # This plugin will be auto-loaded from the ACSM Input plugin. It doesn't make sense for the user
    # to disable it. If necessary, the menu bar button can be removed through the Calibre settings.

    type = "File type"
    # Just so that the GUI extension shows up at the same place as the actual ACSM Input plugin.

    try: 
        installation_type = PluginInstallationType.EXTERNAL
        # Mark this as user-installed so it shows up in the plugin list by default. 
    except: 
        # Setting the Installation type doesn't always work on Calibre 4 and below.
        pass

    actual_plugin = "calibre_plugins.deacsm.migration:ActualMigrationPlugin"

    def is_customizable(self):
        return False


