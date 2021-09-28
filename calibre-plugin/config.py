#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, base64, traceback

from lxml import etree


from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem, QInputDialog, 
                      QLineEdit, QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)

from PyQt5 import Qt as QtGui
from zipfile import ZipFile

# calibre modules and constants.
from calibre.gui2 import (question_dialog, error_dialog, info_dialog, choose_save_file, choose_files)                     # type: ignore
# modules from this plugin's zipfile.
from calibre_plugins.deacsm.__init__ import PLUGIN_NAME, PLUGIN_VERSION      # type: ignore
import calibre_plugins.deacsm.prefs as prefs                                 # type: ignore
from calibre.utils.config import config_dir         # type: ignore


class ConfigWidget(QWidget):
    def __init__(self, plugin_path):
        QWidget.__init__(self)

        self.plugin_path = plugin_path

        # get the prefs
        self.deacsmprefs = prefs.DeACSM_Prefs()

        # make a local copy
        self.tempdeacsmprefs = {}
        self.tempdeacsmprefs['path_to_account_data'] = self.deacsmprefs['path_to_account_data']


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

            self.button_import_activation = QtGui.QPushButton(self)
            self.button_import_activation.setText(_("Import existing activation data (ZIP)"))
            self.button_import_activation.clicked.connect(self.import_activation)
            ua_group_box_layout.addWidget(self.button_import_activation)

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


        update_account_path(self.deacsmprefs["path_to_account_data"])

        self.resize(self.sizeHint())

    def get_account_info(self): 

        activation_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml")
        device_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml")

        container = None
        try: 
            container = etree.parse(activation_xml_path)
            containerdev = etree.parse(device_xml_path)
        except (FileNotFoundError, OSError) as e:
            return "Not authorized for any ADE ID", False, None

        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        
            usernameXML = container.find(adeptNS("credentials")).find(adeptNS("username"))
            devicenameXML = containerdev.find(adeptNS("deviceName"))
            ade_type = usernameXML.get('method', "unknown")
            ade_mail = usernameXML.text
            ade_device_name = devicenameXML.text

            if container.find(adeptNS("activationToken")) == None:
                return "ADE authorization seems to be corrupted (activationToken missing)", False, None

            if container.find(adeptNS("credentials")).find(adeptNS("pkcs12")) == None:
                return "ADE authorization seems to be corrupted (pkcs12 missing)", False, None

            return "Authorized with ADE ID ("+ade_type+") " + ade_mail + "\non device " + ade_device_name, True, ade_mail
        except: 
            return "ADE authorization seems to be corrupted", False, None


    def export_activation(self):

        filters = [("ZIP", ["zip"])]
        filename = choose_save_file(self, "Export ADE activation files", _("Export ADE activation files"), 
                filters, all_files=False, initial_filename="adobe_account_backup.zip")

        if (filename is None):
            return

        print("{0} v{1}: Exporting activation data to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        try: 
            with ZipFile(filename, 'w') as zipfile:
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
        except: 
            return error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=False)

    def import_activation(self):

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
                err = traceback.print_exc()
                return error_dialog(None, "Import failed", "Can't write file", show=True, det_msg=err, show_copy_button=False)

        # update display
        info_string, activated, ade_mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(not activated)
        self.button_import_activation.setEnabled(not activated)
        self.button_export_key.setEnabled(activated)
        self.button_export_activation.setEnabled(activated)

        info_dialog(None, "Done", "Successfully imported authorization for " + ade_mail, show=True, show_copy_button=False)



    def link_account(self):

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

        update_account_path(self.deacsmprefs["path_to_account_data"])
        
        mail, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter mail address")

        if (not ok or mail is None or len(mail) == 0):
            return

        passwd, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter password", QLineEdit.Password)

        if (not ok or passwd is None or len(passwd) == 0):
            return
                
        createDeviceKeyFile()
        createDeviceFile(VAR_HOBBES_VERSION, False)
        success, resp = createUser()
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't create user", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = signIn(mail, passwd)
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Login unsuccessful", det_msg=str(resp), show=True, show_copy_button=True)

        success, resp = activateDevice()
        if (success is False):
            return error_dialog(None, "ADE activation failed", "Couldn't activate device", det_msg=str(resp), show=True, show_copy_button=True)

        print("Authorized to account " + mail)


        # update display
        info_string, activated, mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(False)
        self.button_import_activation.setEnabled(False)
        self.button_export_key.setEnabled(True)
        self.button_export_activation.setEnabled(True)

        info_dialog(None, "Done", "Authorized to account " + mail, show=True, show_copy_button=False)




    def export_key(self):

        try: 
            from calibre_plugins.deacsm.libadobe import update_account_path
            from calibre_plugins.deacsm.libadobeAccount import exportAccountEncryptionKeyDER
        except: 
            try: 
                from libadobe import update_account_path
                from libadobeAccount import exportAccountEncryptionKeyDER
            except: 
                print("{0} v{1}: Error while importing Account stuff".format(PLUGIN_NAME, PLUGIN_VERSION))
                traceback.print_exc()


        update_account_path(self.deacsmprefs["path_to_account_data"])

        filters = [("DER Files", ["der"])]

        filename = choose_save_file(self, "Export ADE keys", _("Export ADE keys"), filters, all_files=False)

        if (filename is None):
            return

        print("{0} v{1}: Exporting encryption key to {2}".format(PLUGIN_NAME, PLUGIN_VERSION, filename))

        ret = exportAccountEncryptionKeyDER(filename)

        if ret:
            return info_dialog(None, "Done", "Key successfully exported", show=True, show_copy_button=False)
        else: 
            return error_dialog(None, "Export failed", "Export failed", show=True, show_copy_button=False)



    def save_settings(self):
        #self.deacsmprefs.set('path_to_account_data', self.txtboxUA.text())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""

