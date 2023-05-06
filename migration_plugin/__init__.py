#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Migration plugin from "DeACSM" to "ACSM Input"
# See README.md for details.

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

# Revision history: 
# v0.0.20: First version of the migration plugin, released under the old name.


from calibre.customize import InterfaceActionBase        # type: ignore

class DeACSMMigrationPlugin(InterfaceActionBase):
    name                        = "DeACSM"
    description                 = "Extension for the ACSM Input plugin to migrate to a new plugin name"
    supported_platforms         = ['linux', 'osx', 'windows']
    author                      = "Leseratte10"
    minimum_calibre_version     = (4, 0, 0)
    version                     = (0, 0, 20)

    can_be_disabled = False

    type = "File type"
    # Just so that the migration extension shows up at the same place as the actual ACSM Input plugin.

    try: 
        from calibre.customize import PluginInstallationType
        installation_type = PluginInstallationType.EXTERNAL
        # Mark this as user-installed so it shows up in the plugin list by default. 
    except: 
        # Setting the Installation type doesn't always work on Calibre 4 and below.
        pass

    actual_plugin = "calibre_plugins.deacsm.migration:ActualMigrationPlugin"

    def is_customizable(self):
        return False


