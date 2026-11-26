#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import os, traceback, threading
from PyQt5.QtGui import QKeySequence

from lxml import etree

import sys


from PyQt5.Qt import (QWidget, QHBoxLayout, QVBoxLayout, QLineEdit, QGroupBox, 
                      QListWidget, QListWidgetItem, QInputDialog, QFileDialog, 
                      QAbstractItemView, QIcon, QDialog, QDialogButtonBox)
from PyQt5.QtWidgets import QShortcut

from PyQt5 import QtCore

from PyQt5 import Qt as QtGui
try: 
    from zipfile import ZipFile, BadZipFile
except: 
    # Python 2
    from zipfile import ZipFile, BadZipfile as BadZipFile

# calibre modules and constants.
from calibre.gui2 import (question_dialog, error_dialog, info_dialog,        # type: ignore
                        warning_dialog, choose_save_file, choose_files)
from calibre.constants import isosx, iswindows, islinux                 # type: ignore

# modules from this plugin's zipfile.
from . import PLUGIN_NAME, PLUGIN_VERSION
from . import prefs
from .keyextractDecryptor import are_wine_binaries_available


if sys.version_info[0] == 2:
    class FileNotFoundError(Exception):
        pass


class BusyDialog(QDialog):
    # A dialog with a message and a busy indicator that run() shows while it waits for work
    # in the background. It can't be closed, because that work can't be stopped.
    #
    # A handler that makes several requests in a row can use one BusyDialog and call run()
    # for each of them. The user then sees a single dialog whose message changes.

    def __init__(self, parent):
        QDialog.__init__(self, parent)
        self.setWindowTitle(PLUGIN_NAME)
        self.setModal(True)
        layout = QVBoxLayout(self)
        self.label = QtGui.QLabel(self)
        layout.addWidget(self.label)
        busy = QtGui.QProgressBar(self)
        busy.setRange(0, 0)     # no known end, so Qt shows a busy indicator
        # Wide enough for the messages, so the dialog keeps its size when they change. On the
        # dialog itself, a minimum width would also keep a longer message from widening it.
        busy.setMinimumWidth(300)
        layout.addWidget(busy)

        self.hide_timer = QtCore.QTimer(self)     # see the end of run()
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.hide)

    def run(self, message, function, *args):
        # Calls function(*args) and returns what it returns, or raises what it raises, like a
        # normal call. But it runs in a separate thread, while this one (Calibre's GUI thread)
        # shows the dialog with the message and keeps handling events. So Calibre doesn't
        # freeze or show "Not responding" during network requests, and as the dialog is modal,
        # the user can't start anything else in the meantime.
        #
        # Only the GUI thread may use Qt widgets, so function must not show dialogs or change
        # the settings window. The handlers show their dialogs before or after this call.

        self.hide_timer.stop()      # busy again, so the dialog stays open
        self.label.setText(message)
        if not self.isVisible():
            self.show()

        result = {}

        def work():
            try:
                result["value"] = function(*args)
            except BaseException as e:
                result["error"] = e

        worker = threading.Thread(target=work, name="ACSM Input background work")
        worker.daemon = True    # don't keep Calibre from exiting

        loop = QtCore.QEventLoop()
        timer = QtCore.QTimer()
        timer.timeout.connect(lambda: worker.is_alive() or loop.quit())

        worker.start()
        timer.start(50)
        loop.exec_()            # handles events until the timer sees that the thread is done
        timer.stop()

        # Don't hide the dialog yet, but the next time the GUI thread handles events: when
        # the handler shows another dialog (like an error message) or is done. So if the
        # handler calls run() again right away, the dialog stays open.
        self.hide_timer.start(0)

        if "error" in result:
            raise result["error"]
        return result["value"]

    def reject(self):
        # Esc would close the dialog
        pass

    def closeEvent(self, event):
        event.ignore()


def run_in_background(parent, message, function, *args):
    # BusyDialog.run() with a dialog of its own, for a handler that makes a single request
    busy = BusyDialog(parent)
    try:
        return busy.run(message, function, *args)
    finally:
        busy.deleteLater()


class ConfigWidget(QWidget):
    def __init__(self, plugin_path):
        QWidget.__init__(self)

        self.plugin_path = plugin_path

        # get the prefs
        self.acsmprefs = prefs.ACSMInput_Prefs()


        # Start Qt Gui dialog layout
        layout = QVBoxLayout(self)
        self.setLayout(layout)


        ua_group_box = QGroupBox(_('Account information:'), self)
        layout.addWidget(ua_group_box)
        ua_group_box_layout = QVBoxLayout()
        ua_group_box.setLayout(ua_group_box_layout)

        info_string, activated, mail = self.get_account_info()

        self.lblAccInfo = QtGui.QLabel(self)
        self.lblAccInfo.setText(info_string)
        ua_group_box_layout.addWidget(self.lblAccInfo)

        if not activated: 
            self.button_link_account = QtGui.QPushButton(self)
            self.button_link_account.setText(_("Link to Digital Editions account"))
            self.button_link_account.clicked.connect(self.link_account)
            ua_group_box_layout.addWidget(self.button_link_account)

            self.button_anon_auth = QtGui.QPushButton(self)
            self.button_anon_auth.setText(_("Create anonymous authorization"))
            self.button_anon_auth.clicked.connect(self.create_anon_auth)
            ua_group_box_layout.addWidget(self.button_anon_auth)

            if isosx:
                self.button_import_MacADE = QtGui.QPushButton(self)
                self.button_import_MacADE.setText(_("Import activation from Digital Editions (MacOS)"))
                self.button_import_MacADE.clicked.connect(self.import_activation_from_MAC)
                ua_group_box_layout.addWidget(self.button_import_MacADE)

            if iswindows:
                self.button_import_WinADE = QtGui.QPushButton(self)
                self.button_import_WinADE.setText(_("Import activation from Digital Editions (Windows)"))
                self.button_import_WinADE.clicked.connect(self.import_activation_from_Win)
                ua_group_box_layout.addWidget(self.button_import_WinADE)

            if islinux and are_wine_binaries_available():
                self.button_import_LinuxWineADE = QtGui.QPushButton(self)
                self.button_import_LinuxWineADE.setText(_("Import activation from Digital Editions (Wine)"))
                self.button_import_LinuxWineADE.clicked.connect(self.import_activation_from_LinuxWine)
                ua_group_box_layout.addWidget(self.button_import_LinuxWineADE)

            self.button_import_activation = QtGui.QPushButton(self)
            self.button_import_activation.setText(_("Import existing activation backup (ZIP)"))
            self.button_import_activation.clicked.connect(self.import_activation_from_ZIP)
            ua_group_box_layout.addWidget(self.button_import_activation)

        else:

            if mail is None: 
                # Current auth is anon auth. Offer to link to account.
                self.button_convert_anon_to_account = QtGui.QPushButton(self)
                self.button_convert_anon_to_account.setText(_("Connect anonymous auth to ByteBooks account"))
                self.button_convert_anon_to_account.clicked.connect(self.convert_anon_to_account)
                ua_group_box_layout.addWidget(self.button_convert_anon_to_account)  

            if mail is not None: 
                # We do have an email. Offer to manage devices / eReaders
                # This isn't really tested a lot ...
                self.button_manage_ext_device = QtGui.QPushButton(self)
                self.button_manage_ext_device.setText(_("Authorize eReader over USB"))
                self.button_manage_ext_device.clicked.connect(self.manage_ext_device)
                ua_group_box_layout.addWidget(self.button_manage_ext_device)




        self.button_export_key = QtGui.QPushButton(self)
        self.button_export_key.setText(_("Export account encryption key"))
        self.button_export_key.clicked.connect(self.export_key)
        self.button_export_key.setEnabled(activated)
        ua_group_box_layout.addWidget(self.button_export_key)

        self.button_export_activation = QtGui.QPushButton(self)
        self.button_export_activation.setText(_("Export account activation data"))
        self.button_export_activation.clicked.connect(self.export_activation)
        self.button_export_activation.setEnabled(activated)
        ua_group_box_layout.addWidget(self.button_export_activation)

        self.button_rented_books = QtGui.QPushButton(self)
        self.button_rented_books.setText(_("Show loaned books"))
        self.button_rented_books.clicked.connect(self.show_rented_books)
        self.button_rented_books.setEnabled(activated)
        ua_group_box_layout.addWidget(self.button_rented_books)


        # First remove all overdue books from the loan list, 
        # to determine if we should enable the button.

        from .libadobeLoans import remove_overdue_books_from_list
        self.acsmprefs.update_loan_list(remove_overdue_books_from_list)


        if (len(self.acsmprefs["list_of_rented_books"]) == 0):
            self.button_rented_books.setText(_("No loaned books available"))
            self.button_rented_books.setEnabled(False)


        self.chkNotifyFulfillment = QtGui.QCheckBox("Notify CS server after successful fulfillment")
        self.chkNotifyFulfillment.setToolTip("Default: True\n\nIf this is enabled, the CS server will receive a notification once the ACSM has successfully been converted. \nThis is not strictly necessary, but it is what Digital Editions does, so it's probably safer to just do it as well.\nAlso, it is required to be able to return loaned books.")
        self.chkNotifyFulfillment.setChecked(self.acsmprefs["notify_fulfillment"])
        layout.addWidget(self.chkNotifyFulfillment)

        self.chkDetailedLogging = QtGui.QCheckBox("Enable verbose debug logging")
        self.chkDetailedLogging.setToolTip("Default: False\n\nIf this is enabled, the plugin debug logs will be more verbose which might be helpful in case of errors.\nHowever, it will also mean that private data like encryption keys or account credentials might end up in the logfiles.")
        self.chkDetailedLogging.setChecked(self.acsmprefs["detailed_logging"])
        self.chkDetailedLogging.toggled.connect(self.toggle_logging)
        layout.addWidget(self.chkDetailedLogging)

        self.chkDeleteAfterFulfill = QtGui.QCheckBox("Delete ACSM file after successful import")
        self.chkDeleteAfterFulfill.setToolTip("Default: False\n\nIf this is enabled, imported ACSM files will be automatically deleted after they've been converted into an EPUB or PDF. \nNote: This is experimental. It is possible that the ACSM will also be deleted if there's errors during import. \nIf you have an important ACSM file that you can't re-download if needed, do not enable this option.")
        self.chkDeleteAfterFulfill.setChecked(self.acsmprefs["delete_acsm_after_fulfill"])
        self.chkDeleteAfterFulfill.toggled.connect(self.toggle_acsm_delete)
        layout.addWidget(self.chkDeleteAfterFulfill)


        # Key shortcut Ctrl+Shift+D / Cmd+Shift+D to remove authorization, just like in ADE.
        self.deauthShortcut = QShortcut(QKeySequence("Ctrl+Shift+D"), self)
        self.deauthShortcut.activated.connect(self.delete_ade_auth)

        try: 
            from .libadobe import update_account_path, are_ade_version_lists_valid

            update_account_path(self.acsmprefs["path_to_account_data"])
            self.resize(self.sizeHint())
    
            # Someone reported getting this error after upgrading the plugin.
            # No idea why that happens - put a try/catch around just to be safe.
            if not are_ade_version_lists_valid():
                # Internal error, this should never happen
                if not activated:
                    self.button_link_account.setEnabled(False)
                    self.button_anon_auth.setEnabled(False)
                    self.button_import_activation.setEnabled(False)
                    if isosx:
                        self.button_import_MacADE.setEnabled(activated)
                    if iswindows:
                        self.button_import_WinADE.setEnabled(activated)
                    if islinux and are_wine_binaries_available():
                        self.button_import_LinuxWineADE.setEnabled(activated)
                else:
                    try: 
                        self.button_convert_anon_to_account.setEnabled(False)
                    except: 
                        pass
                self.button_export_key.setEnabled(False)
                self.button_export_activation.setEnabled(False)
                self.button_rented_books.setEnabled(False)
                self.chkNotifyFulfillment.setEnabled(False)

                error_dialog(None, "Internal error", "Version list mismatch. Please open a bug report.", show=True, show_copy_button=False)
        except UnboundLocalError:
            print("Verify function are_ade_version_lists_valid() not found - why?")
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


    def toggle_logging(self): 
        if not self.chkDetailedLogging.isChecked():
            return

        msg = "You have enabled verbose logging.\n"
        msg += "This will cause various data to be included in the logfiles, like encryption keys, account keys and other confidential data.\n"
        msg += "With this setting enabled, only share log files privately with the developer and don't make them publicly available."

        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)

    def toggle_acsm_delete(self): 
        if not self.chkDeleteAfterFulfill.isChecked():
            return

        msg = "You have enabled ACSM auto-deletion.\n"
        msg += "This means that your source ACSM file will be deleted after import - not just from Calibre, but from the source filesystem, too. "
        msg += "As this feature is experimental, it's possible that ACSMs will also sometimes get deleted even when the import failed.\n\n"
        msg += "If you're importing an ACSM that you cannot re-download in case of issues, do not enable this option!"

        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)

    def manage_ext_device(self): 
        # Unfortunately, I didn't find a nice cross-platform API to query for USB mass storage devices.
        # So just open up a folder picker dialog and have the user select the eReader's root folder. 

        try: 
            from .libadobe import update_account_path, VAR_VER_HOBBES_VERSIONS, safe_xml_parser
            from .libadobeAccount import activateDevice, exportProxyAuth
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        update_account_path(self.acsmprefs["path_to_account_data"])

        info_string, activated, mail = self.get_account_info()

        if not activated:
            return
        
        if mail is None: 
            return

        msg = "Please select the eBook reader you want to link to your account.\n"
        msg += "Either select the root drive / mountpoint, or any folder on the eReader.\n"
        msg += "Note that this feature is experimental and only works with eReaders that "
        msg += "export their .adobe-digital-editions folder."

        info_dialog(None, "Authorize eReader", msg, show=True, show_copy_button=False)

        dialog = QFileDialog()
        try: 
            dialog.setFileMode(QFileDialog.FileMode.Directory)
        except AttributeError:
            # Older Calibre
            dialog.setFileMode(QFileDialog.Directory)

        opts = dialog.options()

        try: 
            opts |= QFileDialog.Option.ShowDirsOnly
        except AttributeError:
            # Older Calibre
            opts |= QFileDialog.ShowDirsOnly

        dialog.setOptions(opts)

        if dialog.exec_():
            x = dialog.selectedFiles()[0]
            if not os.path.isdir(x):
                # This is not supposed to happen.
                error_dialog(None, "Authorize eReader", "Device not found", show=True, show_copy_button=False)
                return

            idx = 0
            while True: 
                idx = idx + 1
                if idx > 15: 
                    # Failsafe, max. 15 folder levels.
                    error_dialog(None, "Authorize eReader", "Didn't find a compatible eReader in that location. (Too many levels)", show=True, show_copy_button=False)
                    return

                adobe_path = os.path.join(x, ".adobe-digital-editions")
                print("Checking " + adobe_path)
                if os.path.isdir(adobe_path):
                    print("Found Adobe path at " + adobe_path)
                    break
                
                x_old = x
                x = os.path.dirname(x)

                if x_old == x:
                    # We're at the drive root and still didn't find an activation
                    error_dialog(None, "Authorize eReader", "Didn't find a compatible eReader in that location. (No Folder)", show=True, show_copy_button=False)
                    return

            if not os.path.isfile(os.path.join(adobe_path, "device.xml")):
                error_dialog(None, "Authorize eReader", "Didn't find a compatible eReader in that location. (No File)", show=True, show_copy_button=False)
                return

            dev_xml_path = os.path.join(adobe_path, "device.xml")
            act_xml_path = os.path.join(adobe_path, "activation.xml")

            dev_xml_tree = etree.parse(dev_xml_path, parser=safe_xml_parser())
            adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
            try: 
                devClass = dev_xml_tree.find("./%s" % (adNS("deviceClass"))).text
                devName = dev_xml_tree.find("./%s" % (adNS("deviceName"))).text
            except: 
                error_dialog(None, "Authorize eReader", "Reader data is invalid.", show=True, show_copy_button=False)
                return
            
            try: 
                devSerial = None
                devSerial = dev_xml_tree.find("./%s" % (adNS("deviceSerial"))).text
            except:
                pass
            

            print("Found Reader with Class " + devClass + " and Name " + devName)

            already_activated = False

            if os.path.isfile(act_xml_path) and os.path.getsize(act_xml_path) > 0:

                active_device_act = etree.parse(act_xml_path, parser=safe_xml_parser())
                adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
                act_uuid = active_device_act.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
                act_username_name = None
                try: 
                    act_username = active_device_act.find("./%s/%s" % (adNS("credentials"), adNS("username")))
                    act_username_name = act_username.text
                    act_username_method = act_username.get("method", "AdobeID")
                except:
                    pass
            
                try: 
                    act_dev_uuid = None
                    act_dev_uuid = active_device_act.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text
                except:
                    pass

                msg = "The following device:\n\n"
                msg += "Path: " + os.path.dirname(adobe_path) + "\n"
                msg += "Type: " + devClass + "\n"
                msg += "Name: " + devName + "\n"
                if devSerial is not None: 
                    msg += "Serial: " + devSerial + "\n"
                if act_dev_uuid is not None: 
                    msg += "UUID: " + act_dev_uuid + "\n"

                
                msg += "\nis already connected to the following ID:\n\n"
                msg += "UUID: " + act_uuid + "\n"
                if (act_username_name is not None):
                    msg += "Username: " + act_username_name + "\n"
                    msg += "Type: " + act_username_method + "\n"
                else: 
                    msg += "Type: anonymous authorization\n"

                msg += "\nDo you want to remove this authorization and link this device to your ByteBooks ID?\n\n"
                msg += "Click \"No\" to cancel, or \"Yes\" to remove the existing authorization from the device and authorize it with your ByteBooks ID."

                ok = question_dialog(None, "Authorize eReader", msg)

                if (not ok): 
                    return

                already_activated = True

            else:   
                msg = "Found an unactivated eReader:\n\n"
                msg += "Path: " + os.path.dirname(adobe_path) + "\n"
                msg += "Type: " + devClass + "\n"
                msg += "Name: " + devName + "\n"
                if devSerial is not None: 
                    msg += "Serial: " + devSerial + "\n"
                msg += "\nDo you want to authorize this device with your ByteBooks ID?"

                ok = question_dialog(None, "Authorize eReader", msg)
                if not ok: 
                    return


            # Okay, if we end up here, the user wants to authorize his eReader to his current ByteBooks ID. 
            # Figure out what ADE version we're currently emulating: 

            device_xml_path = os.path.join(self.acsmprefs["path_to_account_data"], "device.xml")

            try: 
                containerdev = etree.parse(device_xml_path)
            except (IOError, FileNotFoundError, OSError) as e:
                return error_dialog(None, "Failed", "Error while reading device.xml", show=True, show_copy_button=False)

            try: 
                adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        

                # Determine the ADE version we're emulating:
                ver = containerdev.findall("./%s" % (adeptNS("version")))

                # Default to BDE 5.0
                v_idx = 0

                hobbes_version = None
                for f in ver:
                    if f.get("name") == "hobbes":
                        hobbes_version = f.get("value")

                if hobbes_version is not None:
                    try: 
                        v_idx = VAR_VER_HOBBES_VERSIONS.index(hobbes_version)
                    except: 
                        pass
                    
            except:
                return error_dialog(None, "Authorize eReader", "Error while determining DE version", show=True, show_copy_button=False)


            # Activate the target device with that version.
            ret, data = run_in_background(self, "Authorizing the eReader ...", activateDevice, v_idx, dev_xml_tree)

            if not ret: 
                return error_dialog(None, "Authorize eReader", "Couldn't activate device, server returned error.", show=True, det_msg=data, show_copy_button=False)

            # If the reader was already activated with another ID, this replaces that
            # authorization, but only once the new one is written completely.
            ret, data = exportProxyAuth(act_xml_path, data)

            if not ret: 
                return error_dialog(None, "Authorize eReader", "Error while writing activation to device.", show=True, det_msg=data, show_copy_button=False)


            return info_dialog(None, "Authorize eReader", "Reader authorized successfully.", show=True, show_copy_button=False)
            
        
        
    def delete_ade_auth(self): 
        # This function can only be triggered with the key combination Ctrl+Shift+D.
        # There is no easy-to-access button to trigger that to prevent people from 
        # accidentally deleting their authorization. 

        info_string, activated, ade_mail = self.get_account_info()

        if not activated:
            # If there is no authorization, there's nothing to delete
            return

        msg = "Are you sure you want to remove the Digital Editions authorization?\n"

        if ade_mail is None:
            msg += "The current authorization is an anonymous login. It will be permanently lost if you proceed.\n\n"
        else:
            msg += "You will use up one of your ten activations if you want to authorize your account again in the future.\n\n"
        
        msg += "Click 'Yes' to delete the authorization or 'No' to cancel."

        ok = question_dialog(None, "Remove Digital Editions account", msg)

        if (not ok): 
            return

        msg = "Do you want to create a backup of the current authorization?\n"
        msg += "This backup can be imported again without using up one of your authorizations.\n\n"
        msg += "Click 'Yes' to create a backup before deleting, click 'No' to delete without backup."


        ok = question_dialog(None, "Remove Digital Editions account", msg)

        if (ok): 
            # Create a backup:
            backup_success = self.export_activation()
            if (not backup_success):
                error_dialog(None, "Export failed", "The backup was unsuccessful - authorization will not be deleted.", show=True, show_copy_button=False)
                return
        
        # Okay, once we are here, we can be pretty sure the user actually wants to delete their authorization.
        try: 
            os.remove(os.path.join(self.acsmprefs["path_to_account_data"], "activation.xml"))
            os.remove(os.path.join(self.acsmprefs["path_to_account_data"], "device.xml"))
            os.remove(os.path.join(self.acsmprefs["path_to_account_data"], "devicesalt"))
        except:
            error_dialog(None, "Remove Digital Editions account", "There was an error while removing the authorization.", show=True, show_copy_button=False)
            return

        
        # Show success, then close:
        info_dialog(None, "Remove Digital Editions account", "Authorization successfully removed.", show=True, show_copy_button=False)
            
        if ade_mail is None: 
            try: 
                self.button_convert_anon_to_account.setEnabled(False)
            except:
                pass
        self.button_export_activation.setEnabled(False)
        self.button_export_key.setEnabled(False)
        self.lblAccInfo.setText("Authorization deleted.\nClose and re-open this window to add a new authorization.")


    def update_account_display(self):
        # type: () -> tuple
        # Shows the current authorization in the dialog and enables the buttons that fit it.
        # Returns the same as get_account_info(). Which buttons exist depends on the platform
        # and on whether there was an authorization when the dialog was opened (__init__).

        info_string, activated, mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        for name, enabled in [
                ("button_link_account", not activated),
                ("button_anon_auth", not activated),
                ("button_import_MacADE", not activated),
                ("button_import_WinADE", not activated),
                ("button_import_LinuxWineADE", not activated),
                ("button_import_activation", not activated),
                ("button_convert_anon_to_account", mail is None),
                ("button_export_key", activated),
                ("button_export_activation", activated)]:
            button = getattr(self, name, None)
            if button is not None:
                button.setEnabled(enabled)

        self.resize(self.sizeHint())

        return info_string, activated, mail


    def get_account_info(self): 

       
        try: 
            from .libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS
            from .libadobeFulfill import getDecryptedCert, is_bytebooks_account
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        activation_xml_path = os.path.join(self.acsmprefs["path_to_account_data"], "activation.xml")
        device_xml_path = os.path.join(self.acsmprefs["path_to_account_data"], "device.xml")

        container = None
        try: 
            container = etree.parse(activation_xml_path)
            containerdev = etree.parse(device_xml_path)
        except (IOError, FileNotFoundError, OSError) as e:
            return "Not authorized for any ID", False, None
        except (etree.XMLSyntaxError):
            return "Authorization XML files corrupted", False, None


        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        
            devicenameXML = containerdev.find(adeptNS("deviceName"))
            ade_device_name = devicenameXML.text
            
            anon = False
            try: 
                usernameXML = container.find(adeptNS("credentials")).find(adeptNS("username"))
                ade_type = usernameXML.get('method', "unknown")
                ade_mail = usernameXML.text
            except: 
                anon = True
            

            # Determine the ADE version we're emulating:
            ver = containerdev.findall("./%s" % (adeptNS("version")))
            ADE_version = "(unknown)"
            hobbes_version = None

            for f in ver:
                if f.get("name") == "hobbes":
                    hobbes_version = f.get("value")
            
            if hobbes_version is not None:
                try: 
                    v_idx = VAR_VER_HOBBES_VERSIONS.index(hobbes_version)
                    ADE_version = VAR_VER_SUPP_CONFIG_NAMES[v_idx]
                except:
                    pass

            if container.find(adeptNS("activationToken")) == None:
                return "DE authorization seems to be corrupted (activationToken missing)", False, None

            if is_bytebooks_account():
                acc_type = "ByteBooks"
            else: 
                acc_type = "Adobe"

            if getDecryptedCert(None, acc_type == "ByteBooks") is None:
                return "DE authorization seems to be corrupted (failed to decrypt pkcs12)", False, None


            if not anon: 
                ade_type_str = " (" + ade_type + ")"
                if ade_type == "AdobeID":
                    ade_type_str = ""

                display_str = "Authorized with "+ acc_type +" ID"+ade_type_str + " " + ade_mail + "\non device " + ade_device_name + ", emulating " + ADE_version + "."

                if acc_type != "ByteBooks":
                    display_str += "\n\nNote: Your authorization still uses the old Adobe format, not the new ByteBooks format."
                    display_str += "\nYou will run into issues downloading books from any server running CS7 or newer."
                    display_str += "\nPlease remove your authorization by pressing Ctrl+Shift+D, then re-authorize with a ByteBooks ID."

                return display_str, True, ade_mail
            else: 
                display_str = "Authorized with an anonymous "+acc_type+" ID\non device " + ade_device_name + ", emulating " + ADE_version + "."
                if acc_type != "ByteBooks":
                    display_str += "\n\nNote: Your authorization still uses the old Adobe format, not the new ByteBooks format."
                    display_str += "\nYou will run into issues downloading books from any server running CS7 or newer."
                    display_str += "\nPlease remove your authorization by pressing Ctrl+Shift+D, then re-authorize."
                
                return display_str, True, None
        except: 
            traceback.print_exc()
            return "DE authorization seems to be corrupted", False, None


    def export_activation(self):

        try: 
            from .libadobe import update_account_path
            from .libadobeAccount import getAccountUUID
            from .libadobeFulfill import is_bytebooks_account
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()
            return False


        update_account_path(self.acsmprefs["path_to_account_data"])

        prefix = "adobe" if not is_bytebooks_account() else "bytebooks"
        
        try: 
            account_uuid = getAccountUUID()
            export_filename = prefix + "_account_backup_uuid_" + account_uuid + ".zip"
        except:
            account_uuid = None
            export_filename = prefix + "_account_backup.zip"

        filters = [("ZIP", ["zip"])]
        filename = choose_save_file(self, "Export activation files", _("Export activation files"), 
                filters, all_files=False, initial_filename=export_filename)

        if (filename is None):
            return False

        print("{0} v{1}: Exporting activation data to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        try: 
            with ZipFile(filename, 'w') as zipfile:
                zipfile.write(os.path.join(self.acsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                zipfile.write(os.path.join(self.acsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                zipfile.write(os.path.join(self.acsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
            
            return True
        except: 
            error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=False)
            return False

    def check_ADE_registry(self, wineprefix):
        # Gets a path to a WINEPREFIX and returns the activations in its Wine registry, as
        # read_wine_activations() returns them, or None if it has no complete ADE or BDE
        # activation (the same check as in the import, see choose_activation()).

        try: 
            from .libadobeImportAccount import read_wine_activations, choose_activation
            activations = read_wine_activations(wineprefix)
            if choose_activation(activations)[0] is not None:
                return activations
        except:
            print("Exception while validating WINEPREFIX:")
            print(traceback.format_exc())

        return None

    def import_activation_from_LinuxWine(self):
        # This will try to import the activation from Digital Editions on Linux / Wine ...

        msg = "Trying to import existing activation from Digital Editions in WINE ...\n"
        msg += "Note: Importing the activation can take up to 30 seconds, and Calibre will appear to be \"stuck\" during that time.\n\n"
        msg += "Please enter the full, absolute path to your WINEPREFIX."
        msg += "If there's already a path in the input box, it is usually (but not always) the correct one."

        default_path = ""

        # The activations read from each WINEPREFIX, so that its registry is only read once,
        # even if it's checked for the default path, then checked again and imported.
        activations = {}

        def check_registry(wineprefix):
            if wineprefix not in activations:
                activations[wineprefix] = self.check_ADE_registry(wineprefix)
            return activations[wineprefix]

        if (default_path == ""):
            # Check WINEPREFIX env variable
            env_wineprefix = os.getenv("WINEPREFIX", None)
            if (env_wineprefix is not None and os.path.isdir(env_wineprefix)):
                if check_registry(env_wineprefix):
                    default_path = env_wineprefix

        if (default_path == ""):
            # Use default path ".wine" in HOME dir
            home_wineprefix = os.path.join(os.path.expanduser("~"), ".wine")
            if (os.path.isdir(home_wineprefix)):
                if check_registry(home_wineprefix):
                    default_path = home_wineprefix

        
        text, ok = QInputDialog.getText(self, "Importing authorization", msg, text=default_path)

        if (not ok):
            return

        if (not os.path.isdir(text)):
            return error_dialog(None, "Import failed", "The WINEPREFIX path you entered doesn't seem to exist.", show=True, show_copy_button=False)

        if (not check_registry(text)):
            return error_dialog(None, "Import failed", "The WINEPREFIX you entered doesn't seem to contain an authorized DE.", show=True, show_copy_button=False)


        from .libadobe import update_account_path
        from .libadobeImportAccount import importADEactivationLinuxWine

        ret, msg = importADEactivationLinuxWine(text, activations=check_registry(text))

        if (ret):
            update_account_path(self.acsmprefs["path_to_account_data"])           

            # update display
            info_string, activated, ade_mail = self.update_account_display()

            if (activated):
                if ade_mail is None: 
                    info_dialog(None, "Done", "Successfully imported an anonymous authorization", show=True, show_copy_button=False)
                else: 
                    info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)
            else: 
                error_dialog(None, "Import failed", "Import looks like it worked, but the resulting files seem to be corrupted ...", show=True, show_copy_button=False)
        else: 
            error_dialog(None, "Import failed", "That didn't work:\n" + msg, show=True, show_copy_button=False)


    def import_activation_from_Win(self):
        # This will try to import the activation from Digital Editions on Windows ...

        from .libadobe import update_account_path
        from .libadobeImportAccount import importADEactivationWindows

        ret, msg = importADEactivationWindows()

        if (ret):
            update_account_path(self.acsmprefs["path_to_account_data"])

            # update display
            info_string, activated, ade_mail = self.update_account_display()

            if (activated):
                if ade_mail is None: 
                    info_dialog(None, "Done", "Successfully imported an anonymous authorization", show=True, show_copy_button=False)
                else: 
                    info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)
            else: 
                error_dialog(None, "Import failed", "Import looks like it worked, but the resulting files seem to be corrupted ...", show=True, show_copy_button=False)
        else: 
            error_dialog(None, "Import failed", "That didn't work:\n" + msg, show=True, show_copy_button=False)

    def import_activation_from_MAC(self):
        # This will try to import the activation from Digital Editions on MacOS ...

        msg = "Trying to import existing activation from Digital Editions ...\n"
        msg += "You might get a prompt asking you to unlock your keychain / enter your keychain password.\n"
        msg += "This is necessary to extract the encryption keys. "

        info_dialog(None, "Importing from Digital Editions", msg, show=True, show_copy_button=False)

        from .libadobe import update_account_path
        from .libadobeImportAccount import importADEactivationMac

        ret, msg = importADEactivationMac()

        if (ret):
            update_account_path(self.acsmprefs["path_to_account_data"])

            # update display
            info_string, activated, ade_mail = self.update_account_display()

            if (activated):
                if ade_mail is None: 
                    info_dialog(None, "Done", "Successfully imported an anonymous authorization", show=True, show_copy_button=False)
                else: 
                    info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)
            else: 
                error_dialog(None, "Import failed", "Import looks like it worked, but the resulting files seem to be corrupted ...", show=True, show_copy_button=False)
        else: 
            error_dialog(None, "Import failed", "That didn't work:\n" + msg, show=True, show_copy_button=False)



    def import_activation_from_ZIP(self):

        filters = [("ZIP", ["zip"])]
        filenames = choose_files(self, "Import DE activation file (ZIP)", _("Import DE activation file (ZIP)"), 
                filters, all_files=False, select_only_single_file=True)

        from .libadobe import update_account_path, safe_xml_parser, write_files_atomically
        from .libadobeAccount import changeDeviceVersion
        
        try: 
            filename = filenames[0]
            if (filename is None):
                return
        except: 
            return

        print("{0} v{1}: Importing activation data from {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        try: 
            with ZipFile(filename, 'r') as zipfile:
                try: 
                    device = zipfile.read("device.xml")
                    activation = zipfile.read("activation.xml")
                    salt = zipfile.read("devicesalt")
                except: 
                    return error_dialog(None, "Import failed", "Can't find required files in this ZIP", show=True, show_copy_button=False)

                # Check the XML files for the correct format, and ensure they don't use any DOCTYPE declarations.
                for name, data in [("device.xml", device), ("activation.xml", activation)]:
                    try:
                        doctype = etree.fromstring(data, parser=safe_xml_parser()).getroottree().docinfo.doctype
                    except etree.XMLSyntaxError:
                        return error_dialog(None, "Import failed", name + " in this ZIP isn't valid XML.", show=True, show_copy_button=False)
                    if doctype:
                        return error_dialog(None, "Import failed", name + " in this ZIP has invalid format.", show=True, show_copy_button=False)

                try: 
                    # Copy the files byte for byte, so they're not re-encoded with the system's
                    # default encoding, and replace all three together.
                    account_folder = self.acsmprefs["path_to_account_data"]
                    write_files_atomically([
                        (os.path.join(account_folder, "device.xml"), device),
                        (os.path.join(account_folder, "activation.xml"), activation),
                        (os.path.join(account_folder, "devicesalt"), salt),
                    ])

                except: 
                    err = traceback.format_exc()
                    return error_dialog(None, "Import failed", "Can't write file", show=True, det_msg=err, show_copy_button=False)
        except BadZipFile:
            return error_dialog(None, "Import failed", "The file you selected doesn't seem to be a ZIP file.", 
                                show=True, show_copy_button=False)


        update_account_path(self.acsmprefs["path_to_account_data"])
        changeDeviceVersion(0, onlyIfUnknown=True)
        
        # update display
        info_string, activated, ade_mail = self.update_account_display()

        if activated:
            if ade_mail is None: 
                info_dialog(None, "Done", "Successfully imported an anonymous authorization.", show=True, show_copy_button=False)
            else: 
                info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)
        else: 
            error_dialog(None, "Import failed", "That didn't work:\n" + info_string, show=True, show_copy_button=False)

           

    def show_activation_server_error(self, step):
        # Call this from inside an except block so the traceback ends up in the details.
        msg = "Couldn't connect to the ByteBooks activation server (" + step + ").\n\n"
        msg += "Please check your internet connection. If the details below mention a certificate error, "
        msg += "your system's CA certificates might be missing or outdated."
        return error_dialog(None, "Digital Editions activation failed", msg, det_msg=traceback.format_exc(), show=True, show_copy_button=True)


    def create_authorization(self, vers_idx, acc_type, mail, passwd, authCert_bb = None, authCert_adobe = None):
        # type: (int, str, str, str, str, str) -> bool
        # Creates a new authorization: device key, device.xml, user, sign-in and activation.
        # The steps run in a new folder next to the account folder, and the account files are
        # only replaced once all of them worked, so a failed attempt (like a wrong password)
        # leaves the current files as they are. Returns True on success. On failure, it has
        # already shown an error dialog and returns False.

        import tempfile, shutil
        from .libadobe import createDeviceKeyFile, update_account_path, write_files_atomically
        from .libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
        from .libadobeFulfill import getDecryptedCert, is_bytebooks_account

        title = "Digital Editions activation failed"
        account_folder = self.acsmprefs["path_to_account_data"]

        try:
            new_folder = tempfile.mkdtemp(prefix="new_authorization_", dir=os.path.dirname(os.path.abspath(account_folder)))
        except Exception:
            error_dialog(None, title, "Couldn't create a folder for the new authorization", det_msg=traceback.format_exc(), show=True, show_copy_button=True)
            return False

        # Once the server has activated the device, keep the new files if they can't be installed.
        keep_new_folder = False

        # One dialog for all requests, so the user sees its message change from step to step
        busy = BusyDialog(self)

        update_account_path(new_folder)
        try:
            createDeviceKeyFile()
            createDeviceFile(False, vers_idx)
            try:
                success, resp = busy.run("Querying ActivationServiceInfo ...", createUser, vers_idx, authCert_bb, authCert_adobe)
            except Exception:
                self.show_activation_server_error("while creating the user")
                return False
            if (success is False):
                error_dialog(None, title, "Couldn't create user", det_msg=str(resp), show=True, show_copy_button=True)
                return False

            success, resp = busy.run("Signing in ...", signIn, acc_type, mail, passwd)
            if (success is False):
                error_dialog(None, title, "Login unsuccessful", det_msg=str(resp), show=True, show_copy_button=True)
                return False

            success, resp = busy.run("Activating the device ...", activateDevice, vers_idx, None)
            if (success is False):
                error_dialog(None, title, "Couldn't activate device", det_msg=str(resp), show=True, show_copy_button=True)
                return False

            # Don't replace the current files with an authorization that can't be used.
            if getDecryptedCert(None, is_bytebooks_account()) is None:
                error_dialog(None, title, "The new authorization can't be decrypted (failed to decrypt pkcs12)", show=True, show_copy_button=True)
                return False

            keep_new_folder = True
            files = []
            for name in ("devicesalt", "device.xml", "activation.xml"):
                with open(os.path.join(new_folder, name), "rb") as f:
                    files.append((os.path.join(account_folder, name), f.read()))
            write_files_atomically(files)
            keep_new_folder = False

            return True

        except Exception:
            msg = "Unexpected error while creating the authorization."
            if keep_new_folder:
                msg += "\n\nThe device has been activated, but the new authorization couldn't be saved. "
                msg += "Its files are in " + new_folder
            error_dialog(None, title, msg, det_msg=traceback.format_exc(), show=True, show_copy_button=True)
            return False

        finally:
            update_account_path(account_folder)
            if not keep_new_folder:
                shutil.rmtree(new_folder, ignore_errors=True)
            busy.deleteLater()


    def create_anon_auth(self): 
    
        try: 
            from .libadobe import update_account_path
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.acsmprefs["path_to_account_data"])

        msg = "You are about to create an anonymous authorization.\n"
        msg += "If you lose access to this authorization, all books linked to it will be lost / inaccessible. "
        msg += "Make sure to create backups of the authorization data!"
        
        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)
                        
        if not self.create_authorization(0, "anonymous", "", ""):
            return

        print("Authorized to anonymous account")


        # update display
        info_string, activated, mail = self.update_account_display()

        if not activated:
            return error_dialog(None, "Digital Editions activation failed", "That didn't work:\n" + info_string, show=True, show_copy_button=False)

        info_dialog(None, "Done", "Authorized to anonymous account.", show=True, show_copy_button=False)

    
    def convert_anon_to_account(self): 
        try: 
            from .libadobe import update_account_path
            from .libadobeAccount import convertAnonAuthToAccount
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.acsmprefs["path_to_account_data"])

        # This MUST only be called on anonymous accounts. 
        # The button should be disabled if that's not the case, but just to make sure ...
        info_string, activated, mail = self.get_account_info()
        if (not activated):
            return

        if (mail is not None):
            return 

        msg = "You are about to link your anonymous authorization to a ByteBooks ID. "
        msg += "This only works ONCE for each ByteBooks ID. The anonymous authorization will then "
        msg += "permanently be connected to your ByteBooks ID. This is intended for cases where the user "
        msg += "has started with an anonymous authorization, and then creates a fresh ID later "
        msg += "and doesn't want to lose his books.\n\n"
        msg += "Only continue if you fully understand this."


        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)

       
        mail, ok = QInputDialog.getText(self, "Authorizing DE account", "Please enter mail address")

        if (not ok or mail is None or len(mail) == 0):
            return

        passwd, ok = QInputDialog.getText(self, "Authorizing DE account", "Please enter password", QLineEdit.Password)

        if (not ok or passwd is None or len(passwd) == 0):
            return

        success, message = run_in_background(self, "Linking the anonymous authorization ...", convertAnonAuthToAccount, mail, passwd)

        if (success):
            # update display
            info_string, activated, mail = self.update_account_display()

            return info_dialog(None, "Done", "Successfully converted anonymous authentication to ByteBooks ID", show=True, show_copy_button=False)

        else: 
            err_msg = "Could not link anonymous authentication to ByteBooks ID.\n"
            err_msg += "This only works with a fresh ID that has never been linked to any Digital Editions install."

            return error_dialog(None, "DE activation failed", err_msg, det_msg=str(message), show=True, show_copy_button=True)


    
    def link_account(self):

        try: 
            from .libadobe import update_account_path
            from .libadobeAccount import getAuthMethodsAndCert
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.acsmprefs["path_to_account_data"])


        # Get account types
        try:
            types, authCert_bb, authCert_adobe = run_in_background(self, "Loading the list of ID providers ...", getAuthMethodsAndCert)
        except Exception:
            return self.show_activation_server_error("while loading the list of ID providers")
                
        msg = "Please select your ID provider (usually ByteBooks ID)"

        acc_item, ok = QInputDialog.getItem(self, "Authorizing Digital Editions account", msg, types[1], 0, False)

        if (not ok):
            return

        acc_type = "AdobeID"
        try: 
            acc_idx = types[1].index(acc_item)
            acc_type = types[0][acc_idx]
            print("User has selected account type " + acc_type)
        except ValueError:
            return error_dialog(None, "Digital Editions activation failed", "Invalid provider", show=True, show_copy_button=True)


        
        mail, ok = QInputDialog.getText(self, "Authorizing Digital Editions account", "Please enter mail address")

        if (not ok or mail is None or len(mail) == 0):
            return

        passwd, ok = QInputDialog.getText(self, "Authorizing Digital Editions account", "Please enter password", QLineEdit.Password)

        if (not ok or passwd is None or len(passwd) == 0):
            return

        vers_idx = 0
                
        if not self.create_authorization(vers_idx, acc_type, mail, passwd, authCert_bb, authCert_adobe):
            return

        print("Authorized to '" + acc_type + "' account " + mail)


        # update display
        info_string, activated, mail = self.update_account_display()

        if not activated:
            return error_dialog(None, "Digital Editions activation failed", "That didn't work:\n" + info_string, show=True, show_copy_button=False)

        info_dialog(None, "Done", "Authorized to '" + acc_item + "' account " + str(mail), show=True, show_copy_button=False)




    def export_key(self):

        try: 
            from .libadobe import update_account_path
            from .libadobeAccount import exportAccountEncryptionKeyDER, getAccountUUID
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        update_account_path(self.acsmprefs["path_to_account_data"])

        filters = [("DER Files", ["der"])]

        account_uuid = None
        export_filename = "bytebooks_encryption_key.der"
        try: 
            account_uuid = getAccountUUID()
            export_filename = "bytebooks_uuid_" + account_uuid + ".der"
        except:
            pass

        filename = choose_save_file(self, "Export Digital Editions keys", _("Export Digital Editions keys"), filters, 
                    all_files=False, initial_filename=export_filename)

        if (filename is None):
            return

        print("{0} v{1}: Exporting encryption key to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        ret = exportAccountEncryptionKeyDER(filename)

        if ret:
            return info_dialog(None, "Done", "Key successfully exported", show=True, show_copy_button=False)
        else: 
            return error_dialog(None, "Export failed", "Export failed", show=True, show_copy_button=False)



    def save_settings(self):
        self.acsmprefs.set('notify_fulfillment', self.chkNotifyFulfillment.isChecked())
        self.acsmprefs.set('detailed_logging', self.chkDetailedLogging.isChecked())
        self.acsmprefs.set('delete_acsm_after_fulfill', self.chkDeleteAfterFulfill.isChecked())

    def load_resource(self, name):
        # TODO: Figure out what the heck this function is used for, doesn't seem to be called anywhere.
        # Maybe for Calibre 4 / Python 2 compatibility?
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""



    def show_rented_books(self):
        d = RentedBooksDialog(self)
        d.exec_()


class RentedBooksDialog(QDialog):

    def __init__(self, parent):
        QDialog.__init__(self,parent)
        self.parent = parent

        self.setWindowTitle("ACSM Input: Manage loaned Books")
        self.acsmprefs = prefs.ACSMInput_Prefs()

        from .libadobeLoans import remove_overdue_books_from_list
        self.acsmprefs.update_loan_list(remove_overdue_books_from_list)

        # Start Qt Gui dialog layout
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        keys_group_box = QGroupBox("List of loaned books", self)
        layout.addWidget(keys_group_box)
        keys_group_box_layout = QHBoxLayout()
        keys_group_box.setLayout(keys_group_box_layout)

        self.listy = QListWidget(self)
        self.listy.setToolTip("List of loaned books")
        self.listy.setSelectionMode(QAbstractItemView.SingleSelection)
        self.populate_list()
        keys_group_box_layout.addWidget(self.listy)


        button_layout = QVBoxLayout()
        keys_group_box_layout.addLayout(button_layout)
        self._add_key_button = QtGui.QToolButton(self)
        self._add_key_button.setIcon(QIcon(I('view-refresh.png')))
        self._add_key_button.setToolTip("Return book to library")
        self._add_key_button.clicked.connect(self.return_book)
        button_layout.addWidget(self._add_key_button)

        self._delete_key_button = QtGui.QToolButton(self)
        self._delete_key_button.setToolTip(_("Delete book entry from list"))
        self._delete_key_button.setIcon(QIcon(I('list_remove.png')))
        self._delete_key_button.clicked.connect(self.delete_book_entry)
        button_layout.addWidget(self._delete_key_button)

        self.lblAccInfo = QtGui.QLabel(self)
        self.lblAccInfo.setText("Click the arrow button to return a loaned book to the library.\nClick the red X to delete the loan record without returning the book.")
        layout.addWidget(self.lblAccInfo)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

        self.resize(self.sizeHint())

    def populate_list(self):
        self.listy.clear()

        from .libadobeLoans import get_remaining_loan_time, td_format

        for book in self.acsmprefs["list_of_rented_books"]:

            remaining = get_remaining_loan_time(book)
            if remaining is not None:
                info = "(" + td_format(remaining) + " remaining)"
            else:
                # Invalid book timestamp
                info = "(unknown time remaining)"


            book_name = book["book_name"]
            if book_name is None: 
                book_name = "(unknown book)"

            item = QListWidgetItem(book_name + " " + info)
            item.setData(QtCore.Qt.UserRole, book["loanID"])
            self.listy.addItem(item)


    def return_book(self): 
        if not self.listy.currentItem(): 
            return

        userdata = str(self.listy.currentItem().data(QtCore.Qt.UserRole))
        print("Returning book %s (ID %s)" % (self.listy.currentItem().text(), userdata))


        try: 
            from .libadobeFulfill import tryReturnBook
            from .libadobeAccount import getAccountUUID
            from .libadobeLoans import is_loan_mine
        except: 
            print("{0} v{1}: Error while importing book return stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        ret_book = None
        for book in self.acsmprefs["list_of_rented_books"]:
            if book["loanID"] == userdata:
                ret_book = book
                break

        if ret_book is None: 
            return

        # The return request is signed with the current account's key, so the server
        # only accepts it for books that this account borrowed.
        if not is_loan_mine(ret_book):
            account_uuid = getAccountUUID()
            print("Not returning book: it was loaned by %s, but the current account is urn:uuid:%s" % (ret_book["user"], account_uuid))
            return info_dialog(None, "Book not returned",
                    "This book was loaned by a different account. You can only return books that were loaned by the account you're currently authorized with.",
                    det_msg="Loaned by: %s\nCurrent account: urn:uuid:%s" % (ret_book["user"], account_uuid),
                    show=True, show_copy_button=False)

        ret, msg = run_in_background(self, "Returning the book ...", tryReturnBook, ret_book)

        if (ret):
            print("Book successfully returned.")
            self.delete_book_entry(nomsg=True)
            self.populate_list()
            return info_dialog(None, "Done", "Book successfully returned", show=True, show_copy_button=False)
        else: 
            print("Book return failed:")
            print(msg)
            return error_dialog(None, "Error", "Book return failed", det_msg=msg, show=True, show_copy_button=False)


    def delete_book_entry(self, nomsg = False): 
        if not self.listy.currentItem(): 
            return

        userdata = str(self.listy.currentItem().data(QtCore.Qt.UserRole))
        print("Deleting book entry %s (ID %s)" % (self.listy.currentItem().text(), userdata))

        success = self.acsmprefs.remove_loan(userdata)

        self.populate_list()

        if success and not nomsg:
            return info_dialog(None, "Done", "Book entry deleted without returning.", show=True, show_copy_button=False)
        if not nomsg: 
            return error_dialog(None, "Error", "Error while deleting book entry", show=True, show_copy_button=False)
