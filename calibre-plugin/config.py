#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, base64, traceback
from PyQt5.QtGui import QKeySequence

from lxml import etree

import time, datetime


from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem, QInputDialog, 
                      QFileDialog, 
                      QLineEdit, QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)
from PyQt5.QtWidgets import QShortcut

from PyQt5 import QtCore

from PyQt5 import Qt as QtGui
from zipfile import ZipFile

# calibre modules and constants.
from calibre.gui2 import (question_dialog, error_dialog, info_dialog,        # type: ignore
                        warning_dialog, choose_save_file, choose_files)
# modules from this plugin's zipfile.
from calibre_plugins.deacsm.__init__ import PLUGIN_NAME, PLUGIN_VERSION      # type: ignore
import calibre_plugins.deacsm.prefs as prefs                                 # type: ignore
from calibre.utils.config import config_dir         # type: ignore
from calibre.constants import isosx, iswindows, islinux                 # type: ignore


#@@CALIBRE_COMPAT_CODE@@

if sys.version_info[0] == 2:
    class FileNotFoundError(Exception):
        pass


class ConfigWidget(QWidget):
    def __init__(self, plugin_path):
        QWidget.__init__(self)

        self.plugin_path = plugin_path

        # get the prefs
        self.deacsmprefs = prefs.DeACSM_Prefs()

        # make a local copy
        self.tempdeacsmprefs = {}
        self.tempdeacsmprefs['path_to_account_data'] = self.deacsmprefs['path_to_account_data']

        self.tempdeacsmprefs['notify_fulfillment'] = self.deacsmprefs['notify_fulfillment']
        self.tempdeacsmprefs['detailed_logging'] = self.deacsmprefs['detailed_logging']
        self.tempdeacsmprefs['delete_acsm_after_fulfill'] = self.deacsmprefs['delete_acsm_after_fulfill']

        self.tempdeacsmprefs['list_of_rented_books'] = self.deacsmprefs['list_of_rented_books']


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
            self.button_link_account.setText(_("Link to ADE account"))
            self.button_link_account.clicked.connect(self.link_account)
            ua_group_box_layout.addWidget(self.button_link_account)

            self.button_anon_auth = QtGui.QPushButton(self)
            self.button_anon_auth.setText(_("Create anonymous authorization"))
            self.button_anon_auth.clicked.connect(self.create_anon_auth)
            ua_group_box_layout.addWidget(self.button_anon_auth)

            if isosx:
                self.button_import_MacADE = QtGui.QPushButton(self)
                self.button_import_MacADE.setText(_("Import activation from ADE (MacOS)"))
                self.button_import_MacADE.clicked.connect(self.import_activation_from_MAC)
                ua_group_box_layout.addWidget(self.button_import_MacADE)

            if iswindows:
                self.button_import_WinADE = QtGui.QPushButton(self)
                self.button_import_WinADE.setText(_("Import activation from ADE (Windows)"))
                self.button_import_WinADE.clicked.connect(self.import_activation_from_Win)
                ua_group_box_layout.addWidget(self.button_import_WinADE)

            if islinux:
                self.button_import_LinuxWineADE = QtGui.QPushButton(self)
                self.button_import_LinuxWineADE.setText(_("Import activation from ADE (Wine)"))
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
                self.button_convert_anon_to_account.setText(_("Connect anonymous auth to ADE account"))
                self.button_convert_anon_to_account.clicked.connect(self.convert_anon_to_account)
                ua_group_box_layout.addWidget(self.button_convert_anon_to_account)  

            if mail is not None: 
                # We do have an email. Offer to manage devices / eReaders
                # This isn't really tested a lot ...
                self.button_manage_ext_device = QtGui.QPushButton(self)
                self.button_manage_ext_device.setText(_("Authorize eReader over USB"))
                self.button_manage_ext_device.clicked.connect(self.manage_ext_device)
                ua_group_box_layout.addWidget(self.button_manage_ext_device)

            self.button_switch_ade_version = QtGui.QPushButton(self)
            self.button_switch_ade_version.setText(_("Change ADE version"))
            self.button_switch_ade_version.clicked.connect(self.switch_ade_version)
            ua_group_box_layout.addWidget(self.button_switch_ade_version)


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

        if (len(self.deacsmprefs["list_of_rented_books"]) == 0):
            self.button_rented_books.setEnabled(False)


        self.chkNotifyFulfillment = QtGui.QCheckBox("Notify ACS server after successful fulfillment")
        self.chkNotifyFulfillment.setToolTip("Default: True\n\nIf this is enabled, the ACS server will receive a notification once the ACSM has successfully been converted. \nThis is not strictly necessary, but it is what ADE does, so it's probably safer to just do it as well.\nAlso, it is required to be able to return loaned books.")
        self.chkNotifyFulfillment.setChecked(self.tempdeacsmprefs["notify_fulfillment"])
        layout.addWidget(self.chkNotifyFulfillment)

        self.chkDetailedLogging = QtGui.QCheckBox("Enable verbose debug logging")
        self.chkDetailedLogging.setToolTip("Default: False\n\nIf this is enabled, the plugin debug logs will be more verbose which might be helpful in case of errors.\nHowever, it will also mean that private data like encryption keys or account credentials might end up in the logfiles.")
        self.chkDetailedLogging.setChecked(self.tempdeacsmprefs["detailed_logging"])
        self.chkDetailedLogging.toggled.connect(self.toggle_logging)
        layout.addWidget(self.chkDetailedLogging)

        self.chkDeleteAfterFulfill = QtGui.QCheckBox("Delete ACSM file after successful import")
        self.chkDeleteAfterFulfill.setToolTip("Default: False\n\nIf this is enabled, imported ACSM files will be automatically deleted after they've been converted into an EPUB or PDF. \nNote: This is experimental. It is possible that the ACSM will also be deleted if there's errors during import. \nIf you have an important ACSM file that you can't re-download if needed, do not enable this option.")
        self.chkDeleteAfterFulfill.setChecked(self.tempdeacsmprefs["delete_acsm_after_fulfill"])
        self.chkDeleteAfterFulfill.toggled.connect(self.toggle_acsm_delete)
        layout.addWidget(self.chkDeleteAfterFulfill)

        # Key shortcut Ctrl+Shift+D / Cmd+Shift+D to remove authorization, just like in ADE.
        self.deauthShortcut = QShortcut(QKeySequence("Ctrl+Shift+D"), self)
        self.deauthShortcut.activated.connect(self.delete_ade_auth)



        try: 
            from libadobe import createDeviceKeyFile, update_account_path, are_ade_version_lists_valid
            from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        update_account_path(self.deacsmprefs["path_to_account_data"])
        self.resize(self.sizeHint())

        try: 
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
                    if islinux:
                        self.button_import_LinuxWineADE.setEnabled(activated)
                else:
                    self.button_switch_ade_version.setEnabled(False)
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
            from libadobe import update_account_path, VAR_VER_HOBBES_VERSIONS
            from libadobeAccount import activateDevice, exportProxyAuth
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        update_account_path(self.deacsmprefs["path_to_account_data"])

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
        dialog.setFileMode(QFileDialog.Directory)
        opts = dialog.options()
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
                    error_dialog(None, "Authorize eReader", "Didn't find an ADE-compatible eReader in that location. (Too many levels)", show=True, show_copy_button=False)
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
                    error_dialog(None, "Authorize eReader", "Didn't find an ADE-compatible eReader in that location. (No Folder)", show=True, show_copy_button=False)
                    return

            if not os.path.isfile(os.path.join(adobe_path, "device.xml")):
                error_dialog(None, "Authorize eReader", "Didn't find an ADE-compatible eReader in that location. (No File)", show=True, show_copy_button=False)
                return

            dev_xml_path = os.path.join(adobe_path, "device.xml")
            act_xml_path = os.path.join(adobe_path, "activation.xml")

            dev_xml_tree = etree.parse(dev_xml_path)
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

            if os.path.isfile(act_xml_path):

                active_device_act = etree.parse(act_xml_path)
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

                
                msg += "\nis already connected to the following AdobeID:\n\n"
                msg += "UUID: " + act_uuid + "\n"
                if (act_username_name is not None):
                    msg += "Username: " + act_username_name + "\n"
                    msg += "Type: " + act_username_method + "\n"
                else: 
                    msg += "Type: anonymous authorization\n"

                msg += "\nDo you want to remove this authorization and link this device to your AdobeID?\n\n"
                msg += "Click \"No\" to cancel, or \"Yes\" to remove the existing authorization from the device and authorize it with your AdobeID."

                ok = question_dialog(None, "Authorize eReader", msg)

                if (not ok): 
                    return

                try: 
                    os.remove(act_xml_path)
                except: 
                    error_dialog(None, "Authorize eReader", "Failed to remove existing authorization.", show=True, show_copy_button=False)
                    return

  
            msg = "Found an unactivated eReader:\n\n"
            msg += "Path: " + os.path.dirname(adobe_path) + "\n"
            msg += "Type: " + devClass + "\n"
            msg += "Name: " + devName + "\n"
            if devSerial is not None: 
                msg += "Serial: " + devSerial + "\n"
            msg += "\nDo you want to authorize this device with your AdobeID?"

            ok = question_dialog(None, "Authorize eReader", msg)
            if not ok: 
                return


            # Okay, if we end up here, the user wants to authorize his eReader to his current AdobeID. 
            # Figure out what ADE version we're currently emulating: 

            device_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml")

            try: 
                containerdev = etree.parse(device_xml_path)
            except (IOError, FileNotFoundError, OSError) as e:
                return error_dialog(None, "Failed", "Error while reading device.xml", show=True, show_copy_button=False)

            try: 
                adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        

                # Determine the ADE version we're emulating:
                ver = containerdev.findall("./%s" % (adeptNS("version")))

                # "Default" entry would be for the old 10.0.4 entry. 
                # As 10.X is in the 3.0 range, assume we're on ADE 3.0.1 with hobbes version 10.0.85385
                v_idx = VAR_VER_HOBBES_VERSIONS.index("10.0.85385")

                for f in ver:
                    if f.get("name") == "hobbes":
                        hobbes_version = f.get("value")

                if hobbes_version is not None:
                    v_idx = VAR_VER_HOBBES_VERSIONS.index(hobbes_version)
            except:
                return error_dialog(None, "Authorize eReader", "Error while determining ADE version", show=True, show_copy_button=False)


            # Activate the target device with that version.
            ret, data = activateDevice(v_idx, dev_xml_tree)

            if not ret: 
                return error_dialog(None, "Authorize eReader", "Couldn't activate device, server returned error.", show=True, det_msg=data, show_copy_button=False)

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

        msg = "Are you sure you want to remove the ADE authorization?\n"

        if ade_mail is None:
            msg += "The current authorization is an anonymous login. It will be permanently lost if you proceed.\n\n"
        else:
            msg += "You will use up one of your six activations if you want to authorize your account again in the future.\n\n"
        
        msg += "Click 'Yes' to delete the authorization or 'No' to cancel."

        ok = question_dialog(None, "Remove ADE account", msg)

        if (not ok): 
            return

        msg = "Do you want to create a backup of the current authorization?\n"
        msg += "This backup can be imported again without using up one of your authorizations.\n\n"
        msg += "Click 'Yes' to create a backup before deleting, click 'No' to delete without backup."


        ok = question_dialog(None, "Remove ADE account", msg)

        if (ok): 
            # Create a backup:
            backup_success = self.export_activation()
            if (not backup_success):
                error_dialog(None, "Export failed", "The backup was unsuccessful - authorization will not be deleted.", show=True, show_copy_button=False)
                return
        
        # Okay, once we are here, we can be pretty sure the user actually wants to delete their authorization.
        try: 
            os.remove(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"))
            os.remove(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"))
            os.remove(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"))
        except:
            error_dialog(None, "Remove ADE account", "There was an error while removing the authorization.", show=True, show_copy_button=False)

        
        # Show success, then close:
        info_dialog(None, "Remove ADE account", "ADE authorization successfully removed.", show=True, show_copy_button=False)
            

        try: 
            self.button_switch_ade_version.setEnabled(False)
        except:
            pass
        if ade_mail is None: 
            try: 
                self.button_convert_anon_to_account.setEnabled(False)
            except:
                pass
        self.button_export_activation.setEnabled(False)
        self.button_export_key.setEnabled(False)
        self.lblAccInfo.setText("Authorization deleted.\nClose and re-open this window to add a new authorization.")


    def get_account_info(self): 

       
        try: 
            from libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        activation_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml")
        device_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml")

        container = None
        try: 
            container = etree.parse(activation_xml_path)
            containerdev = etree.parse(device_xml_path)
        except (IOError, FileNotFoundError, OSError) as e:
            return "Not authorized for any ADE ID", False, None

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
            ADE_version = None

            for f in ver:
                if f.get("name") == "hobbes":
                    hobbes_version = f.get("value")
            
            if hobbes_version is not None:
                try: 
                    v_idx = VAR_VER_HOBBES_VERSIONS.index(hobbes_version)
                    ADE_version = VAR_VER_SUPP_CONFIG_NAMES[v_idx] + " (" + hobbes_version + ")"

                except:
                    # Version not present, probably the "old" 10.0.4 entry. 
                    # As 10.X is in the 3.0 range, assume we're on ADE 3.0
                    ADE_version = "ADE 3.0.1 (" + hobbes_version + ")"
          

            if container.find(adeptNS("activationToken")) == None:
                return "ADE authorization seems to be corrupted (activationToken missing)", False, None

            if container.find(adeptNS("credentials")).find(adeptNS("pkcs12")) == None:
                return "ADE authorization seems to be corrupted (pkcs12 missing)", False, None

            if not anon: 
                return "Authorized with ADE ID ("+ade_type+") " + ade_mail + "\non device " + ade_device_name + ", emulating " + ADE_version + ".", True, ade_mail
            else: 
                return "Authorized with an anonymous ADE ID\non device " + ade_device_name + ", emulating " + ADE_version + ".", True, None
        except: 
            traceback.print_exc()
            return "ADE authorization seems to be corrupted", False, None


    def export_activation(self):

        try: 
            from libadobe import update_account_path
            from libadobeAccount import getAccountUUID
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()
            return False


        update_account_path(self.deacsmprefs["path_to_account_data"])

        account_uuid = None
        export_filename = "adobe_account_backup.zip"
        try: 
            account_uuid = getAccountUUID()
            export_filename = "adobe_account_backup_uuid_" + account_uuid + ".zip"
        except:
            pass

        filters = [("ZIP", ["zip"])]
        filename = choose_save_file(self, "Export ADE activation files", _("Export ADE activation files"), 
                filters, all_files=False, initial_filename=export_filename)

        if (filename is None):
            return False

        print("{0} v{1}: Exporting activation data to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        try: 
            with ZipFile(filename, 'w') as zipfile:
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
            
            return True
        except: 
            error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=False)
            return False

    def check_ADE_registry(self, wineprefix):
        # Gets a path to a WINEPREFIX and returns True if this is useable. 
        # Checks if the Wine registry contains an ADE activation.

        try: 
            registry_file = open(os.path.join(wineprefix, "user.reg"))
            while True: 
                line = registry_file.readline()
                if not line:
                    break

                if line.strip().startswith("[Software\\\\Adobe\\\\Adept\\\\Activation\\\\0000"):
                    return True
        
        except:
            print("Exception while validating WINEPREFIX:")
            print(traceback.format_exc())

        return False

    def import_activation_from_LinuxWine(self):
        # This will try to import the activation from Adobe Digital Editions on Linux / Wine ...

        msg = "Trying to import existing activation from Adobe Digital Editions in WINE ...\n"
        msg += "Note: Importing the activation can take up to 30 seconds, and Calibre will appear to be \"stuck\" during that time.\n\n"
        msg += "Please enter the full, absolute path to your WINEPREFIX."
        msg += "If there's already a path in the input box, it is usually (but not always) the correct one."

        default_path = ""

        if (default_path == ""):
            # Check WINEPREFIX env variable
            env_wineprefix = os.getenv("WINEPREFIX", None)
            if (env_wineprefix is not None and os.path.isdir(env_wineprefix)):
                if self.check_ADE_registry(env_wineprefix):
                    default_path = env_wineprefix

        if (default_path == ""):
            # Use default path ".wine" in HOME dir
            home_wineprefix = os.path.join(os.path.expanduser("~"), ".wine")
            if (os.path.isdir(home_wineprefix)):
                if self.check_ADE_registry(home_wineprefix):
                    default_path = home_wineprefix

        
        text, ok = QInputDialog.getText(self, "Importing authorization", msg, text=default_path)

        if (not ok):
            return

        if (not os.path.isdir(text)):
            return error_dialog(None, "Import failed", "The WINEPREFIX path you entered doesn't seem to exist.", show=True, show_copy_button=False)

        if (not self.check_ADE_registry(text)):
            return error_dialog(None, "Import failed", "The WINEPREFIX you entered doesn't seem to contain an authorized ADE.", show=True, show_copy_button=False)


        from libadobeImportAccount import importADEactivationLinuxWine

        ret, msg = importADEactivationLinuxWine(text)

        if (ret):
            # update display
            info_string, activated, ade_mail = self.get_account_info()
            self.lblAccInfo.setText(info_string)

            self.button_link_account.setEnabled(not activated)
            self.button_anon_auth.setEnabled(not activated)
            try: 
                self.button_convert_anon_to_account.setEnabled(ade_mail is None)
            except:
                pass
            self.button_import_activation.setEnabled(not activated)
            self.button_import_LinuxWineADE.setEnabled(not activated)
            self.button_export_key.setEnabled(activated)
            self.button_export_activation.setEnabled(activated)
            

            self.resize(self.sizeHint())

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
        # This will try to import the activation from Adobe Digital Editions on Windows ...

        from libadobeImportAccount import importADEactivationWindows

        ret, msg = importADEactivationWindows()

        if (ret):
            # update display
            info_string, activated, ade_mail = self.get_account_info()
            self.lblAccInfo.setText(info_string)

            self.button_link_account.setEnabled(not activated)
            self.button_anon_auth.setEnabled(not activated)
            try: 
                self.button_convert_anon_to_account.setEnabled(ade_mail is None)
            except:
                pass
            self.button_import_activation.setEnabled(not activated)
            self.button_import_WinADE.setEnabled(not activated)
            self.button_export_key.setEnabled(activated)
            self.button_export_activation.setEnabled(activated)
            

            self.resize(self.sizeHint())

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
        # This will try to import the activation from Adobe Digital Editions on MacOS ...

        msg = "Trying to import existing activation from Adobe Digital Editions ...\n"
        msg += "You might get a prompt asking you to unlock your keychain / enter your keychain password.\n"
        msg += "This is necessary to extract the ADE encryption keys. "

        info_dialog(None, "Importing from ADE", msg, show=True, show_copy_button=False)

        from libadobeImportAccount import importADEactivationMac

        ret, msg = importADEactivationMac()

        if (ret):
            # update display
            info_string, activated, ade_mail = self.get_account_info()
            self.lblAccInfo.setText(info_string)

            self.button_link_account.setEnabled(not activated)
            self.button_anon_auth.setEnabled(not activated)
            try: 
                self.button_convert_anon_to_account.setEnabled(ade_mail is None)
            except:
                pass
            self.button_import_activation.setEnabled(not activated)
            self.button_import_MacADE.setEnabled(not activated)
            self.button_export_key.setEnabled(activated)
            self.button_export_activation.setEnabled(activated)

            self.resize(self.sizeHint())

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
        filenames = choose_files(self, "Import ADE activation file (ZIP)", _("Import ADE activation file (ZIP)"), 
                filters, all_files=False, select_only_single_file=True)
        
        try: 
            filename = filenames[0]
            if (filename is None):
                return
        except: 
            return

        print("{0} v{1}: Importing activation data from {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        with ZipFile(filename, 'r') as zipfile:
            try: 
                device = zipfile.read("device.xml")
                activation = zipfile.read("activation.xml")
                salt = zipfile.read("devicesalt")
            except: 
                return error_dialog(None, "Import failed", "Can't find required files in this ZIP")

            try: 
                output_device = open(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "w")
                output_device.write(device.decode("utf-8"))
                output_device.close()

                output_activation = open(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "w")
                output_activation.write(activation.decode("utf-8"))
                output_activation.close()

                output_salt = open(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "wb")
                output_salt.write(salt)
                output_salt.close()

            except: 
                err = traceback.format_exc()
                return error_dialog(None, "Import failed", "Can't write file", show=True, det_msg=err, show_copy_button=False)

        # update display
        info_string, activated, ade_mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(not activated)
        self.button_anon_auth.setEnabled(not activated)
        try: 
            self.button_convert_anon_to_account.setEnabled(ade_mail is None)
        except:
            pass
        self.button_import_activation.setEnabled(not activated)
        self.button_export_key.setEnabled(activated)
        self.button_export_activation.setEnabled(activated)
        if isosx:
            self.button_import_MacADE.setEnabled(not activated)
        if iswindows:
            self.button_import_WinADE.setEnabled(not activated)
        if islinux:
            self.button_import_LinuxWineADE.setEnabled(not activated)
        
        
        self.resize(self.sizeHint())

        if ade_mail is None: 
            info_dialog(None, "Done", "Successfully imported an anonymous authorization.", show=True, show_copy_button=False)
        else: 
            info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)


    def switch_ade_version(self): 
        try: 
            from libadobe import VAR_VER_HOBBES_VERSIONS, VAR_VER_SUPP_CONFIG_NAMES
            from libadobe import VAR_VER_BUILD_IDS, VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO
            from libadobeAccount import changeDeviceVersion
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        device_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml")

        try: 
            containerdev = etree.parse(device_xml_path)
        except (IOError, FileNotFoundError, OSError) as e:
            return error_dialog(None, "Failed", "Error while reading file", show=True, show_copy_button=False)

        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        

            # Determine the ADE version we're emulating:
            ver = containerdev.findall("./%s" % (adeptNS("version")))

            # "Default" entry would be for the old 10.0.4 entry. 
            # As 10.X is in the 3.0 range, assume we're on ADE 3.0.1 with hobbes version 10.0.85385
            v_idx = VAR_VER_HOBBES_VERSIONS.index("10.0.85385")

            for f in ver:
                if f.get("name") == "hobbes":
                    hobbes_version = f.get("value")

            
            if hobbes_version is not None:
                ADE_version = "ADE 3.0.X (RMSDK " + hobbes_version + ")"
                try: 
                    v_idx = VAR_VER_HOBBES_VERSIONS.index(hobbes_version)
                    ADE_version = VAR_VER_SUPP_CONFIG_NAMES[v_idx] + " (RMSDK " + hobbes_version + ")"
                except:
                    pass
            else: 
                ADE_version = "ADE 3.0.X"


        except: 
            err = traceback.format_exc()
            return error_dialog(None, "Failed", "Error while determining current ADE version.", show=True, det_msg=err, show_copy_button=False)


        # Build a list of allowed strings:
        allowed_strings = []
        for allowed_id in VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO:
            try: 
                idx = VAR_VER_BUILD_IDS.index(allowed_id)
            except:
                pass
        
            try: 
                allowed_strings.append(VAR_VER_SUPP_CONFIG_NAMES[idx])
            except:
                pass
        
        if len(allowed_strings) == 0:
            return error_dialog(None, "Failed", "Error determining available versions", show=True, show_copy_button=True)


        msg = "You are currently using " + ADE_version + "\n"
        msg += "You can switch to a different ADE version by using the selection box below.\n"
        msg += "- ADE 1.7.2 is for debugging only. Do not use this setting, it might get your account banned\n"
        msg += "- ADE 2.0.1 works with most books, and will always get you the old, removable DRM. Select this if you're unsure\n"
        msg += "- ADE 3.0.1 works with all books, but may give you unremovable DRM for some retailers\n"
        msg += "- ADE 4.0.3 and ADE 4.5.11 are available, but aren't really needed for anything\n"
        msg += "Select ADE 2.0.1 if you are unsure\n\n"
        msg += "Which ADE version do you want to emulate?"

        item, ok = QInputDialog.getItem(self, "Change ADE version", msg, allowed_strings, 1, False)

        if (not ok):
            return

        idx = -1
        try: 
            idx = VAR_VER_SUPP_CONFIG_NAMES.index(item)
            ret, msg = changeDeviceVersion(idx)
            if (ret):
                # Update info display:
                info_string, activated, mail = self.get_account_info()
                self.lblAccInfo.setText(info_string)
                return info_dialog(None, "Done", "Successfully switched to " + item, show=True, show_copy_button=False)
            else: 
                return error_dialog(None, "Failed", "Error while changing ADE version: " + msg, show=True, show_copy_button=False)    

        except: 
            return error_dialog(None, "Failed", "Error while changing ADE version.", show=True, det_msg=traceback.format_exc(), show_copy_button=False)
            

    def create_anon_auth(self): 
    
        try: 
            from libadobe import createDeviceKeyFile, update_account_path, VAR_VER_SUPP_CONFIG_NAMES
            from libadobe import VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE, VAR_VER_BUILD_IDS, VAR_VER_DEFAULT_BUILD_ID
            from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.deacsmprefs["path_to_account_data"])

        msg = "You are about to create an anonymous authorization.\n"
        msg += "If you lose access to this authorization, all books linked to it will be lost / inaccessible. "
        msg += "Make sure to create backups of the authorization data! "
        msg += "Also, if you do end up emulating ADE3 or newer, and you receive an eBook with the new DRM, "
        msg += "you might not be able to read / access that book at all."
        
        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)
        
        # Build a list of allowed strings:
        allowed_strings = []

        for allowed_id in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
            idx = VAR_VER_BUILD_IDS.index(allowed_id)
            allowed_strings.append(VAR_VER_SUPP_CONFIG_NAMES[idx])

        
        if len(allowed_strings) == 0:
            return error_dialog(None, "ADE activation failed", "Error determining available versions", show=True, show_copy_button=True)


        msg = "Which ADE version do you want to emulate?\n"
        msg += "- ADE 2.0.1 works with most but not all books, but will always give you the old, removable DRM.\n"
        msg += "- ADE 3.0.1 works with all books, but may give you unremovable DRM for some retailers.\n"
        msg += "- ADE 4.0.3 and 4.5.11 are only provided for completeness sake, but aren't usually needed.\n"
        msg += "Select ADE 2.0 if you are unsure."
        item, ok = QInputDialog.getItem(self, "Authorizing ADE account", msg, allowed_strings, 
            VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE.index(VAR_VER_DEFAULT_BUILD_ID), False)

        if (not ok):
            return

        idx = 0
        try: 
            idx = VAR_VER_SUPP_CONFIG_NAMES.index(item)
            print("User selected ({0}) -> {1}".format(idx, VAR_VER_SUPP_CONFIG_NAMES[idx]))
        except: 
            resp = traceback.format_exc()
            return error_dialog(None, "ADE activation failed", "Error determining version", det_msg=str(resp), show=True, show_copy_button=True)
                
        createDeviceKeyFile()
        createDeviceFile(False, idx)
        success, resp = createUser(idx, None)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't create user", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = signIn("anonymous", "", "")
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Login unsuccessful", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = activateDevice(idx, None)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't activate device", det_msg=str(resp), show=True, show_copy_button=True)

        print("Authorized to anonymous account")


        # update display
        info_string, activated, mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(not activated)
        self.button_anon_auth.setEnabled(not activated)
        try: 
            self.button_convert_anon_to_account.setEnabled(mail is None)
        except:
            pass
        self.button_import_activation.setEnabled(not activated)
        self.button_export_key.setEnabled(activated)
        self.button_export_activation.setEnabled(activated)
        if isosx:
            self.button_import_MacADE.setEnabled(not activated)
        if iswindows:
            self.button_import_WinADE.setEnabled(not activated)
        if islinux:
            self.button_import_LinuxWineADE.setEnabled(not activated)

        self.resize(self.sizeHint())

        info_dialog(None, "Done", "Authorized to anonymous account.", show=True, show_copy_button=False)

    
    def convert_anon_to_account(self): 
        try: 
            from libadobe import createDeviceKeyFile, update_account_path
            from libadobeAccount import convertAnonAuthToAccount
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.deacsmprefs["path_to_account_data"])

        # This MUST only be called on anonymous accounts. 
        # The button should be disabled if that's not the case, but just to make sure ...
        info_string, activated, mail = self.get_account_info()
        if (not activated):
            return

        if (mail is not None):
            return 

        msg = "You are about to link your anonymous authorization to an AdobeID. "
        msg += "This only works ONCE for each AdobeID. The anonymous authorization will then "
        msg += "permanently be connected to your AdobeID. This is intended for cases where the user "
        msg += "has started with an anonymous authorization, and then creates a fresh AdobeID later "
        msg += "and doesn't want to lose his books.\n\n"
        msg += "Only continue if you fully understand this."


        warning_dialog(None, "Warning", msg, show=True, show_copy_button=False)

       
        mail, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter mail address")

        if (not ok or mail is None or len(mail) == 0):
            return

        passwd, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter password", QLineEdit.Password)

        if (not ok or passwd is None or len(passwd) == 0):
            return

        success, message = convertAnonAuthToAccount(mail, passwd)

        if (success):
            # update display
            info_string, activated, mail = self.get_account_info()
            self.lblAccInfo.setText(info_string)

            try: 
                self.button_convert_anon_to_account.setEnabled(mail is None)
            except:
                pass

            self.resize(self.sizeHint())

            return info_dialog(None, "Done", "Successfully converted anonynmous authentication to AdobeID", show=True, show_copy_button=False)

        else: 
            err_msg = "Could not link anonymous authentication to AdobeID.\n"
            err_msg += "This only works with a fresh AdobeID that has never been linked to any ADE install."

            return error_dialog(None, "ADE activation failed", err_msg, det_msg=str(message), show=True, show_copy_button=True)


    
    def link_account(self):

        try: 
            from libadobe import createDeviceKeyFile, update_account_path, VAR_VER_SUPP_CONFIG_NAMES
            from libadobe import VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE, VAR_VER_BUILD_IDS, VAR_VER_DEFAULT_BUILD_ID
            from libadobeAccount import createDeviceFile, getAuthMethodsAndCert, createUser, signIn, activateDevice
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        update_account_path(self.deacsmprefs["path_to_account_data"])


        # Get account types
        types, authCert = getAuthMethodsAndCert()
        
        msg = "Please select your AdobeID provider. Usually, \"Adobe ID\" is the correct choice."

        acc_item, ok = QInputDialog.getItem(self, "Authorizing ADE account", msg, types[1], 0, False)
        acc_type = "AdobeID"
        try: 
            acc_idx = types[1].index(acc_item)
            acc_type = types[0][acc_idx]
            print("User has selected account type " + acc_type)
        except ValueError:
            return error_dialog(None, "ADE activation failed", "Invalid provider", show=True, show_copy_button=True)


        
        mail, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter mail address")

        if (not ok or mail is None or len(mail) == 0):
            return

        passwd, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter password", QLineEdit.Password)

        if (not ok or passwd is None or len(passwd) == 0):
            return

        # Build a list of allowed strings:
        allowed_strings = []

        for allowed_id in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
            idx = VAR_VER_BUILD_IDS.index(allowed_id)
            allowed_strings.append(VAR_VER_SUPP_CONFIG_NAMES[idx])

        
        if len(allowed_strings) == 0:
            return error_dialog(None, "ADE activation failed", "Error determining available versions", show=True, show_copy_button=True)


        msg = "Which ADE version do you want to emulate?\n"
        msg += "- ADE 2.0.1 works with most but not all books, but will always give you the old, removable DRM.\n"
        msg += "- ADE 3.0.1 works with all books, but may give you unremovable DRM for some retailers.\n"
        msg += "- ADE 4.0.3 and 4.5.11 are only provided for completeness sake, but aren't usually needed.\n"
        msg += "Select ADE 2.0 if you are unsure."
        item, ok = QInputDialog.getItem(self, "Authorizing ADE account", msg, allowed_strings, 
            VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE.index(VAR_VER_DEFAULT_BUILD_ID), False)

        if (not ok):
            return

        vers_idx = 0
        try: 
            vers_idx = VAR_VER_SUPP_CONFIG_NAMES.index(item)
            print("User selected ({0}) -> {1}".format(vers_idx, VAR_VER_SUPP_CONFIG_NAMES[vers_idx]))
        except: 
            resp = traceback.format_exc()
            return error_dialog(None, "ADE activation failed", "Error determining version", det_msg=str(resp), show=True, show_copy_button=True)
                
        createDeviceKeyFile()
        createDeviceFile(False, vers_idx)
        success, resp = createUser(vers_idx, authCert)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't create user", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = signIn(acc_type, mail, passwd)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Login unsuccessful", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = activateDevice(vers_idx, None)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't activate device", det_msg=str(resp), show=True, show_copy_button=True)

        print("Authorized to '" + acc_type + "' account " + mail)


        # update display
        info_string, activated, mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(not activated)
        self.button_anon_auth.setEnabled(not activated)
        try: 
            self.button_convert_anon_to_account.setEnabled(mail is None)
        except:
            pass
        self.button_import_activation.setEnabled(not activated)
        self.button_export_key.setEnabled(activated)
        self.button_export_activation.setEnabled(activated)
        if isosx:
            self.button_import_MacADE.setEnabled(not activated)
        if iswindows:
            self.button_import_WinADE.setEnabled(not activated)
        if islinux:
            self.button_import_LinuxWineADE.setEnabled(not activated)

        self.resize(self.sizeHint())

        info_dialog(None, "Done", "Authorized to '" + acc_item + "' account " + mail, show=True, show_copy_button=False)




    def export_key(self):

        try: 
            from libadobe import update_account_path
            from libadobeAccount import exportAccountEncryptionKeyDER, getAccountUUID
        except: 
            print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()


        update_account_path(self.deacsmprefs["path_to_account_data"])

        filters = [("DER Files", ["der"])]

        account_uuid = None
        export_filename = "adobe_encryption_key.der"
        try: 
            account_uuid = getAccountUUID()
            export_filename = "adobe_uuid_" + account_uuid + ".der"
        except:
            pass

        filename = choose_save_file(self, "Export ADE keys", _("Export ADE keys"), filters, 
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
        self.deacsmprefs.set('notify_fulfillment', self.chkNotifyFulfillment.isChecked())
        self.deacsmprefs.set('detailed_logging', self.chkDetailedLogging.isChecked())
        self.deacsmprefs.set('delete_acsm_after_fulfill', self.chkDeleteAfterFulfill.isChecked())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""



    def show_rented_books(self):
        d = RentedBooksDialog(self, self.deacsmprefs["list_of_rented_books"])
        d.exec_()


class RentedBooksDialog(QDialog):
    def __init__(self, parent, booklist):
        QDialog.__init__(self,parent)
        self.parent = parent

        self.setWindowTitle("DeACSM: Manage loaned Books")

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

    def td_format(self, td_object):
        seconds = int(td_object.total_seconds())
        periods = [
            ('y',        60*60*24*365),
            ('M',        60*60*24*30),
            ('d',        60*60*24),
            ('h',        60*60),
            ('m',        60),
            ('s',        1)
        ]

        strings=[]
        tick = 0
        for period_name, period_seconds in periods:
            if seconds > period_seconds:
                period_value , seconds = divmod(seconds, period_seconds)
                strings.append("%s%s" % (period_value, period_name))
                tick += 1
            if tick >= 2:
                break

        return " ".join(strings)

    def populate_list(self):
        self.listy.clear()

        overdue_books = []

        for book in self.parent.deacsmprefs["list_of_rented_books"]:

            try: 
                book_time_stamp = book["validUntil"]
                timestamp = datetime.datetime.strptime(book_time_stamp, "%Y-%m-%dT%H:%M:%SZ")
                currenttime = datetime.datetime.utcnow()
            except: 
                # Invalid book timestano
                continue


            if (timestamp <= currenttime):
                # Book is overdue, no need to return. Delete from list.
                overdue_books.append(book)
                continue
            else: 
                info = "(" + self.td_format(timestamp - currenttime)
                info += " remaining)"


            item = QListWidgetItem(book["book_name"] + " " + info)
            item.setData(QtCore.Qt.UserRole, book["loanID"])
            self.listy.addItem(item)

        for book in overdue_books:
            self.parent.deacsmprefs["list_of_rented_books"].remove(book)

        self.parent.deacsmprefs.writeprefs()


    def return_book(self): 
        if not self.listy.currentItem(): 
            return

        userdata = str(self.listy.currentItem().data(QtCore.Qt.UserRole))
        print("Returning book %s (ID %s)" % (self.listy.currentItem().text(), userdata))


        try: 
            from libadobeFulfill import tryReturnBook
        except: 
            print("{0} v{1}: Error while importing book return stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
            traceback.print_exc()

        Ret_book = None
        for book in self.parent.deacsmprefs["list_of_rented_books"]:
            if book["loanID"] == userdata:
                Ret_book = book
                break

        if Ret_book is None: 
            return

        ret, msg = tryReturnBook(Ret_book)

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

        success = False
        for book in self.parent.deacsmprefs["list_of_rented_books"]:
            if book["loanID"] == userdata:
                self.parent.deacsmprefs["list_of_rented_books"].remove(book)
                success = True
                break

        self.populate_list()

        if success and not nomsg:
            return info_dialog(None, "Done", "Book entry deleted without returning.", show=True, show_copy_button=False)
        if not nomsg: 
            return error_dialog(None, "Error", "Error while deleting book entry", show=True, show_copy_button=False)
