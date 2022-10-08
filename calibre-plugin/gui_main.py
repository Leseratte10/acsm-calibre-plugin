#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GUI for the ACSM plugin. 
#
# "create_menu_action_unique" taken from the Quality Check plugin: 
# GPLv3, Copyright 2011, Grant Drake <grant.drake@gmail.com>


from calibre.gui2.actions import InterfaceAction
from calibre.gui2.actions import menu_action_unique_name
from PyQt5.QtGui import QMenu, QToolButton


#@@CALIBRE_COMPAT_CODE@@


def create_menu_action_unique(ia, parent_menu, menu_text, image=None, tooltip=None,
                       shortcut=None, triggered=None, is_checked=None, shortcut_name=None,
                       unique_name=None, favourites_menu_unique_name=None):
    '''
    Create a menu action with the specified criteria and action, using the new
    InterfaceAction.create_menu_action() function which ensures that regardless of
    whether a shortcut is specified it will appear in Preferences->Keyboard
    '''
    orig_shortcut = shortcut
    kb = ia.gui.keyboard
    if unique_name is None:
        unique_name = menu_text
    if not shortcut == False:
        full_unique_name = menu_action_unique_name(ia, unique_name)
        if full_unique_name in kb.shortcuts:
            shortcut = False
        else:
            if shortcut is not None and not shortcut == False:
                if len(shortcut) == 0:
                    shortcut = None
                else:
                    shortcut = _(shortcut)

    if shortcut_name is None:
        shortcut_name = menu_text.replace('&','')

    ac = ia.create_menu_action(parent_menu, unique_name, menu_text, icon=None, shortcut=shortcut,
        description=tooltip, triggered=triggered, shortcut_name=shortcut_name)
    if shortcut == False and not orig_shortcut == False:
        if ac.calibre_shortcut_unique_name in ia.gui.keyboard.shortcuts:
            kb.replace_action(ac.calibre_shortcut_unique_name, ac)
    #if image:
        #ac.setIcon(get_icons(image, "ACSM Input"))


    return ac

class ActualACSMInputGUIExtension(InterfaceAction):
    name                        = "ACSM Input Plugin GUI Extension"
    
    popup_type = QToolButton.ToolButtonPopupMode.InstantPopup
    action_type = 'global'
    action_spec = ("ACSM Input", None, "ACSM Input Plugin by Leseratte10", None)
    # Text, icon, tooltip, keyboard shortcut

    def genesis(self): 
        print("Genesis!")
        self.menu = QMenu(self.gui)

        self.rebuild_menus()

        self.qaction.setMenu(self.menu)
        icon = get_icons('acsm_logo_2.png', "ACSM Input Plugin")
        self.qaction.setIcon(icon)
        #self.qaction.triggered.connect(self.trigger_config_dialog)

    def rebuild_menus(self):
        m = self.menu
        m.clear()

        create_menu_action_unique(self, m, "ACSM Input configuration", None, shortcut=None, shortcut_name="Open ACSM Input plugin settings dialog", triggered=self.trigger_config_dialog)
        create_menu_action_unique(self, m, "Show loaned books", None, shortcut=None, shortcut_name="ACSM: Open list of loaned books", triggered=self.trigger_loan_dialog)

    
    def trigger_loan_dialog(self):
        import calibre_plugins.deacsm.prefs as prefs
        from calibre.gui2 import info_dialog
        deacsmprefs = prefs.ACSMInput_Prefs()

        from calibre_plugins.deacsm.config import RentedBooksDialog # type: ignore
        RentedBooksDialog.remove_overdue_books_from_list()

        if (len(deacsmprefs["list_of_rented_books"]) == 0):
            return info_dialog(None, "No loaned books", "You currently have no loaned books.", show=True, show_copy_button=False)

        d = RentedBooksDialog(self.gui)
        d.exec_()
        
        

    
    def trigger_config_dialog(self): 
        from calibre.customize.ui import _initialized_plugins
        from calibre_plugins.deacsm.__init__ import PLUGIN_NAME
        from calibre.gui2 import error_dialog

        plg = None
        for plugin in _initialized_plugins:
            if plugin.name == PLUGIN_NAME:
                plg = plugin
                break

        if plg is None:
            msg = "Tried to open the ACSM Input plugin settings, but I couldn't find the ACSM Input plugin. "
            msg += "This is most likely a bug in the plugin. Try restarting Calibre, and if you still get this error, "
            msg += "please open a bug report. "
            return error_dialog(None, "Plugin not found", msg, show=True)

        plg.do_user_config(self.gui)


