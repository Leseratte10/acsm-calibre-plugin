#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, glob, shutil, tarfile, subprocess, time, tempfile, datetime

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

        self.button_compile = QtGui.QPushButton(self)
        self.button_compile.setToolTip(_("Click to compile"))
        self.button_compile.setText(_("Compile"))
        self.button_compile.clicked.connect(self.compile)
        layout.addWidget(self.button_compile)


        ua_group_box = QGroupBox(_('Account information:'), self)
        layout.addWidget(ua_group_box)
        ua_group_box_layout = QVBoxLayout()
        ua_group_box.setLayout(ua_group_box_layout)

        #self.txtboxUA = QtGui.QLineEdit(self)
        #self.txtboxUA.setToolTip(_("Enter folder path to account data"))
        #self.txtboxUA.setText(self.tempdeacsmprefs['path_to_account_data'])
        #ua_group_box_layout.addWidget(self.txtboxUA)

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
            return "Authorized with ADE ID ("+ade_type+") " + ade_mail + "\non device " + ade_device_name, True
        except: 
            return "ADE authorization seems to be corrupted", False


    def export_activation(self):
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")

        filters = [("ZIP", ["zip"])]
        filename = choose_save_file(self, "Export ADE activation files", _("Export ADE activation files"), filters, all_files=False)

        print("would export to " + filename)

        try: 
            with ZipFile(filename, 'w') as zipfile:
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
        except: 
            return error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=False)



    def link_account(self):
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")
        verdir = os.path.join(maindir,PLUGIN_VERSION)

        mail, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter mail address")
        passwd, ok = QInputDialog.getText(self, "Authorizing ADE account", "Please enter password", QLineEdit.Password)
                

        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()

        output_dir = tempfile.mkdtemp()

        my_env = os.environ.copy()
        my_env["LD_LIBRARY_PATH"] = ".:" + my_env["LD_LIBRARY_PATH"]

        # Make backup ...
        if (os.path.exists(os.path.join(deacsmprefs["path_to_account_data"], "device.xml")) or 
            os.path.exists(os.path.join(deacsmprefs["path_to_account_data"], "activation.xml")) or
            os.path.exists(os.path.join(deacsmprefs["path_to_account_data"], "devicesalt")) ): 

            try: 
                currenttime = datetime.datetime.now()
                backup_file = "backup_" + str(currenttime.year) + "-" + str(currenttime.month) + "-" + str(currenttime.day) + "_"
                backup_file += str(currenttime.hour) + "-" + str(currenttime.minute) + "-" + str(currenttime.second) + ".zip"
                with ZipFile(os.path.join(deacsmprefs["path_to_account_data"], backup_file), 'w') as zipfile:
                    try: 
                        zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "device.xml"), "device.xml")
                    except: 
                        pass
                    try: 
                        zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "activation.xml"), "activation.xml")
                    except: 
                        pass
                    try: 
                        zipfile.write(os.path.join(self.deacsmprefs["path_to_account_data"], "devicesalt"), "devicesalt")
                    except: 
                        pass
            except: 
                raise

        ret = None

        try:

            
            ret = subprocess.run([os.path.join(verdir, "adept_activate"), 
            "-u", mail, 
            "-p", passwd, 
            "-O", output_dir,
            "-v"
            ], capture_output=True, shell=False, cwd=verdir, env=my_env)

            print(ret)

        except:
            return error_dialog(None, "ADE activation failed", "ADE activation failed", det_msg=str(ret), show=True, show_copy_button=True)


        try: 
            shutil.copy(os.path.join(output_dir, "device.xml"), os.path.join(deacsmprefs["path_to_account_data"], "device.xml"))
            shutil.copy(os.path.join(output_dir, "activation.xml"), os.path.join(deacsmprefs["path_to_account_data"], "activation.xml"))
            shutil.copy(os.path.join(output_dir, "devicesalt"), os.path.join(deacsmprefs["path_to_account_data"], "devicesalt"))
            shutil.rmtree(output_dir)

            info_dialog(None, "Done", "Authorization successful!", show=True, show_copy_button=False)

        except IndexError: 
            return error_dialog(None, "Authorization failed", "Authorization failed", show=True, det_msg=str(ret), show_copy_button=True)

        # update display
        info_string, activated = self.get_account_info()
        self.lblAccInfo.setText(info_string)

        self.button_link_account.setEnabled(False)
        self.button_export_key.setEnabled(True)
        self.button_export_activation.setEnabled(True)




    def export_key(self):
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")
        verdir = os.path.join(maindir,PLUGIN_VERSION)

        filters = [("DER Files", ["der"])]


        filename = choose_save_file(self, "Export ADE keys", _("Export ADE keys"), filters, all_files=False)

        print("would export to " + filename)

        my_env = os.environ.copy()
        my_env["LD_LIBRARY_PATH"] = ".:" + my_env["LD_LIBRARY_PATH"]


        old_files = glob.glob(os.path.join(verdir, "*.der"))
        for file in old_files:
            try: 
                os.remove(file)
            except:
                pass

        try: 
            os.chmod(os.path.join(verdir, "acsmdownloader"), 0o775)
        except FileNotFoundError:
            return error_dialog(None, "Tool not found", "Helper tool not found. Press \"Compile\" then try again.", show=True, show_copy_button=False)

        ret = None

        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()

        try:
            ret = subprocess.run([os.path.join(verdir, "acsmdownloader"), "-d", os.path.join(deacsmprefs["path_to_account_data"], "device.xml"), 
            "-a", os.path.join(deacsmprefs["path_to_account_data"], "activation.xml"), 
            "-k", os.path.join(deacsmprefs["path_to_account_data"], "devicesalt"), 
            "-e"
            ], capture_output=True, shell=False, cwd=verdir, env=my_env)

            print(ret)

        except:
            return error_dialog(None, "Export failed", "Export failed.", det_msg=str(ret), show=True, show_copy_button=True)

        try: 
            new_key = glob.glob(os.path.join(verdir, "*.der"))[0]
            shutil.move(new_key, filename)
            info_dialog(None, "Done", "Key successfully exported", show=True, show_copy_button=False)
        except IndexError: 
            return error_dialog(None, "Export failed", "Export failed.", show=True, show_copy_button=True)






    def compile(self):

        # Get path to source code:
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")
        verdir = os.path.join(maindir,PLUGIN_VERSION)

        # Delete old version
        try: 
            shutil.rmtree(os.path.join(verdir, "libgourou"))
        except: 
            pass

        # extract source
        with tarfile.open(os.path.join(verdir, "libgourou_bundle_release.tar.xz")) as f:
            f.extractall(verdir)

        # Run script, compile 1st:
        os.chmod(os.path.join(verdir, "libgourou", "scripts", "setup.sh"), 0o775)


        ret1 = subprocess.run([ os.path.join(verdir, "libgourou", "scripts", "setup.sh") ], capture_output=True, shell=True, cwd=os.path.join(verdir, "libgourou"))
        print(ret1)

        ret2 = subprocess.run([ "make", "BUILD_SHARED=1", "BUILD_UTILS=1" ], capture_output=True, shell=True, cwd=os.path.join(verdir, "libgourou"))
        print(ret2)

        try: 
            shutil.copy(os.path.join(verdir, "libgourou", "libgourou.so"), verdir)
            shutil.copy(os.path.join(verdir, "libgourou", "utils", "acsmdownloader"), verdir)
            shutil.copy(os.path.join(verdir, "libgourou", "utils", "adept_activate"), verdir)
            info_dialog(None, "Done", "Compiling successful", show=True, show_copy_button=False)
        except: 
            print("Can't copy ...")
            error_dialog(None, "Compiling failed", "Compiling failed. Did you install all dependencies?", det_msg=str(ret1) + "\n" + str(ret2), show=True, show_copy_button=True)
            


    def save_settings(self):
        #self.deacsmprefs.set('path_to_account_data', self.txtboxUA.text())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""

