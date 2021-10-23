#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, base64, traceback

from lxml import etree

import time, datetime


from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem, QInputDialog, 
                      QLineEdit, QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)

from PyQt5 import QtCore

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

        self.tempdeacsmprefs['notify_fulfillment'] = self.deacsmprefs['notify_fulfillment']

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
                err = traceback.format_exc()
                return error_dialog(None, "Import failed", "Can't write file", show=True, det_msg=err, show_copy_button=False)

        # update display
        info_string, activated, ade_mail = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(not activated)
        self.button_import_activation.setEnabled(not activated)
        self.button_export_key.setEnabled(activated)
        self.button_export_activation.setEnabled(activated)

        self.resize(self.sizeHint())

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

        self.resize(self.sizeHint())

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

        filename = choose_save_file(self, "Export ADE keys", _("Export ADE keys"), filters, 
                    all_files=False, initial_filename="adobe_encryption_key.der")

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
        self.deacsmprefs.set('notify_fulfillment', self.chkNotifyFulfillment.isChecked())
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
                print("Invalid book timestamp")
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
            from calibre_plugins.deacsm.libadobeFulfill import tryReturnBook
        except: 
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
            print("Book successfully returned:")
            print(msg)
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
