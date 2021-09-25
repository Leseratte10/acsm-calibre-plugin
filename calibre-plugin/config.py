#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, base64

from lxml import etree


from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem, QInputDialog, 
                      QLineEdit, QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)

from PyQt5 import Qt as QtGui
from zipfile import ZipFile

# calibre modules and constants.
from calibre.gui2 import (question_dialog, error_dialog, info_dialog, choose_save_file)                     # type: ignore
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

        info_string, activated = self.get_account_info()

        self.lblAccInfo = QtGui.QLabel(self)
        self.lblAccInfo.setText(info_string)
        ua_group_box_layout.addWidget(self.lblAccInfo)

        if not activated: 
            self.button_link_account = QtGui.QPushButton(self)
            self.button_link_account.setText(_("Link to ADE account"))
            self.button_link_account.clicked.connect(self.link_account)
            ua_group_box_layout.addWidget(self.button_link_account)

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
                print("error Account")
                raise
            raise

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
            return "Not authorized for any ADE ID", False

        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        
            usernameXML = container.find(adeptNS("credentials")).find(adeptNS("username"))
            devicenameXML = containerdev.find(adeptNS("deviceName"))
            ade_type = usernameXML.get('method', "unknown")
            ade_mail = usernameXML.text
            ade_device_name = devicenameXML.text

            if container.find(adeptNS("activationToken")) == None:
                return "ADE authorization seems to be corrupted (activationToken missing)", False

            if container.find(adeptNS("credentials")).find(adeptNS("pkcs12")) == None:
                return "ADE authorization seems to be corrupted (pkcs12 missing)", False

            return "Authorized with ADE ID ("+ade_type+") " + ade_mail + "\non device " + ade_device_name, True
        except: 
            return "ADE authorization seems to be corrupted", False


    def export_activation(self):

        filters = [("ZIP", ["zip"])]
        filename = choose_save_file(self, "Export ADE activation files", _("Export ADE activation files"), filters, all_files=False)

        if (filename is None):
            return

        print("would export to " + filename)

        try: 
            with ZipFile(filename, 'w') as zipfile:
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
        except: 
            return error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=False)



    def link_account(self):

        try: 
            from calibre_plugins.deacsm.libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
            from calibre_plugins.deacsm.libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
        except: 
            try: 
                from libadobe import VAR_HOBBES_VERSION, createDeviceKeyFile, update_account_path
                from libadobeAccount import createDeviceFile, createUser, signIn, activateDevice
            except: 
                print("error Account")
                raise
            raise

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
        info_string, activated = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(False)
        self.button_export_key.setEnabled(True)
        self.button_export_activation.setEnabled(True)

        info_dialog(None, "Done", "Authorized to account " + mail, show=True, show_copy_button=False)




    def export_key(self):
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")
        verdir = os.path.join(maindir,PLUGIN_VERSION)

        filters = [("DER Files", ["der"])]

        filename = choose_save_file(self, "Export ADE keys", _("Export ADE keys"), filters, all_files=False)

        if (filename is None):
            return

        print("would export to " + filename)

        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()


        activation_xml_path = os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml")

        container = None
        try: 
            container = etree.parse(activation_xml_path)
        except (FileNotFoundError, OSError) as e:
            return error_dialog(None, "Export failed", "Export failed - Can't open activation.xml", show=True, show_copy_button=False)

        key_binary = None
        try: 
            adeptNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)        
            usernameXML = container.find(adeptNS("credentials")).find(adeptNS("privateLicenseKey"))
            key_base64 = usernameXML.text
            key_binary = base64.decodebytes(key_base64.encode())[26:]
        except: 
            return error_dialog(None, "Export failed", "Export failed - Can't read key from activation.xml", show=True, show_copy_button=False)

        try: 
            output_file = open(filename, "wb")
            output_file.write(key_binary)
            output_file.close()
        except: 
            return error_dialog(None, "Export failed", "Export failed - Can't write key to file", show=True, show_copy_button=False)


        info_dialog(None, "Done", "Key successfully exported", show=True, show_copy_button=False)

    def save_settings(self):
        #self.deacsmprefs.set('path_to_account_data', self.txtboxUA.text())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""

