#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

# GUI for the ACSM plugin. 
#
# "create_menu_action_unique" taken from the Quality Check plugin: 
# GPLv3, Copyright 2011, Grant Drake <grant.drake@gmail.com>


import os, traceback

from calibre.gui2.actions import InterfaceAction
from calibre.gui2.actions import menu_action_unique_name
try: 
    from PyQt5.QtGui import QMenu, QToolButton
except ImportError:
    try: 
        from PyQt5.QtWidgets import QMenu, QToolButton
    except ImportError:
        from PyQt4.Qt import QMenu, QToolButton
try:
    from PyQt5.QtCore import QFileSystemWatcher, QTimer
except ImportError:
    from PyQt4.QtCore import QFileSystemWatcher, QTimer


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
    
    try: 
        popup_type = QToolButton.ToolButtonPopupMode.InstantPopup
    except AttributeError:
        # Needed for Calibre 3
        popup_type = 2

    action_type = 'global'
    action_spec = ("ACSM Input", None, "ACSM Input Plugin by Leseratte10", None)
    # Text, icon, tooltip, keyboard shortcut

    def genesis(self): 
        print("ACSM Input: GUI Plugin Genesis!")
        self.menu = QMenu(self.gui)

        self.rebuild_menus()

        self.qaction.setMenu(self.menu)
        try:
            # Py3 
            icon = get_icons('acsm_logo_2.png', "ACSM Input Plugin")
        except TypeError:
            # Py2
            icon = get_icons('acsm_logo_2.png')

        self.qaction.setIcon(icon)
        #self.qaction.triggered.connect(self.trigger_config_dialog)

    def initialization_complete(self):
        # Keep the loans on authorized eReaders up to date without the user having to do
        # anything: when one is plugged in, and when a new loan arrives while it's plugged in.
        # calibre has no hook for "Send to device", but a book can only be sent after it was
        # imported, so one of the two has always happened before the eReader is unplugged.
        try:
            from calibre.gui2.device import device_signals
            device_signals.device_connection_changed.connect(self.device_connection_changed)
        except:
            traceback.print_exc()

        # The eReader may already have been connected while calibre was starting.
        QTimer.singleShot(1000, self.refresh_reader_on_connect)

        try:
            import calibre_plugins.deacsm.prefs as prefs    # type: ignore
            account_path = prefs.ACSMInput_Prefs()["path_to_account_data"]
            self.account_xml_path = os.path.join(account_path, "activation.xml")

            # Fulfillment runs in a separate worker process, so the new loanToken it stores in
            # the account is the only sign of a new loan that reaches the GUI.
            self.account_watcher = QFileSystemWatcher(self)
            self.account_watcher.addPath(account_path)
            if os.path.isfile(self.account_xml_path):
                self.account_watcher.addPath(self.account_xml_path)
            self.account_watcher.fileChanged.connect(self.account_changed)
            self.account_watcher.directoryChanged.connect(self.account_changed)

            self.new_loan_timer = QTimer(self)
            self.new_loan_timer.setSingleShot(True)
            self.new_loan_timer.timeout.connect(self.refresh_after_new_loan)
            self.new_loan_attempts = 0
        except:
            traceback.print_exc()


    def device_connection_changed(self, connected):
        if connected:
            # Let calibre finish setting up the device first.
            QTimer.singleShot(1000, self.refresh_reader_on_connect)


    def refresh_reader_on_connect(self):
        self.refresh_connected_reader(ask = True)


    def account_changed(self, path):
        # Rewriting a file can make the watcher drop it, and it may not have existed before.
        if os.path.isfile(self.account_xml_path) and self.account_xml_path not in self.account_watcher.files():
            self.account_watcher.addPath(self.account_xml_path)

        # Give the fulfillment a moment to finish writing it.
        self.new_loan_attempts = 0
        self.new_loan_timer.start(1000)


    def refresh_after_new_loan(self):
        from lxml import etree

        try:
            etree.parse(self.account_xml_path)
        except:
            # Still being written, try again a bit later.
            self.new_loan_attempts += 1
            if self.new_loan_attempts < 5:
                self.new_loan_timer.start(1000)
            return

        self.refresh_connected_reader(ask = False)


    def refresh_connected_reader(self, ask):
        try:
            import calibre_plugins.deacsm.prefs as prefs    # type: ignore
            from calibre_plugins.deacsm.linked_readers import (get_account_user,    # type: ignore
                get_reader_authorization, get_reader_name, is_linked_reader, is_declined_reader,
                link_reader, decline_reader, refresh_reader)
            from calibre.gui2 import question_dialog

            if not prefs.ACSMInput_Prefs()["refresh_loans_on_readers"]:
                return

            adobe_path = self.connected_reader_folder()
            if adobe_path is None:
                return

            user, device = get_reader_authorization(adobe_path)
            if device is None or user != get_account_user():
                # Not authorized, or authorized with someone else's AdobeID.
                return

            if not is_linked_reader(device):
                # Authorized with this account, but by ADE or by an older version of the plugin.
                if not ask or is_declined_reader(device):
                    return

                msg = "The eReader \"%s\" is authorized with your AdobeID, " % (get_reader_name(adobe_path))
                msg += "but its library loans aren't kept up to date.\n\n"
                msg += "Authorize this eReader to keep your library loans up to date? "
                msg += "New loans will then be added to it automatically whenever it's connected.\n\n"
                msg += "If you choose \"No\", you won't be asked again for this eReader."

                if not question_dialog(self.gui, "Authorize eReader", msg):
                    decline_reader(device)
                    return

                link_reader(device, get_reader_name(adobe_path))

            ret, msg = refresh_reader(adobe_path)
            if not ret:
                print("ACSM Input: Couldn't refresh the loans on the eReader: " + msg)
                return

            if msg == "Done":
                self.gui.status_bar.show_message("ACSM Input: loans updated on the eReader", 5000)
        except:
            traceback.print_exc()


    def rebuild_menus(self):
        m = self.menu
        m.clear()

        create_menu_action_unique(self, m, "ACSM Input configuration", None, shortcut=None, shortcut_name="Open ACSM Input plugin settings dialog", triggered=self.trigger_config_dialog)
        create_menu_action_unique(self, m, "Show loaned books", None, shortcut=None, shortcut_name="ACSM: Open list of loaned books", triggered=self.trigger_loan_dialog)
        create_menu_action_unique(self, m, "Refresh loans on eReader", None, shortcut=None, shortcut_name="ACSM: Refresh loans on eReader", triggered=self.trigger_refresh_loans)

    
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
        
        

    
    def connected_reader_folder(self):
        # The ADE folder of the eReader calibre currently has mounted, if it has one.
        try:
            prefix = self.gui.device_manager.connected_device._main_prefix
        except:
            return None

        if not prefix:
            return None

        adobe_path = os.path.join(prefix, ".adobe-digital-editions")
        if not os.path.isdir(adobe_path):
            return None

        return adobe_path


    def trigger_refresh_loans(self):
        from calibre.gui2 import choose_dir, error_dialog, info_dialog
        from calibre_plugins.deacsm.linked_readers import find_adobe_folder, refresh_reader    # type: ignore

        title = "Refresh loans on eReader"

        adobe_path = self.connected_reader_folder()
        if adobe_path is None:
            # calibre doesn't see the eReader (or doesn't support it), ask where it is.
            root = choose_dir(self.gui, "acsm-input-refresh-loans-reader", "Select the eReader")
            if not root:
                return

            adobe_path = find_adobe_folder(root)
            if adobe_path is None:
                return error_dialog(self.gui, title, "Didn't find an ADE-compatible eReader in that location.", show=True, show_copy_button=False)

        ret, msg = refresh_reader(adobe_path)
        if not ret:
            return error_dialog(self.gui, title, "Couldn't refresh the loans on the eReader: " + msg, show=True, show_copy_button=False)

        return info_dialog(self.gui, title, "The loans on the eReader are up to date.", show=True, show_copy_button=False)


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


