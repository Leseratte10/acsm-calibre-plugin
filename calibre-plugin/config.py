#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false

import os, glob, shutil, tarfile, subprocess, time

from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem,
                      QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)

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


        ua_group_box = QGroupBox(_('Path to account:'), self)
        layout.addWidget(ua_group_box)
        ua_group_box_layout = QVBoxLayout()
        ua_group_box.setLayout(ua_group_box_layout)

        self.txtboxUA = QtGui.QLineEdit(self)
        self.txtboxUA.setToolTip(_("Enter folder path to account data"))
        self.txtboxUA.setText(self.tempdeacsmprefs['path_to_account_data'])
        ua_group_box_layout.addWidget(self.txtboxUA)

        self.button_export_key = QtGui.QPushButton(self)
        self.button_export_key.setText(_("Export account key"))
        self.button_export_key.clicked.connect(self.export_key)
        ua_group_box_layout.addWidget(self.button_export_key)


        self.resize(self.sizeHint())

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

        except:
            return error_dialog(None, "Export failed", "Export failed.", det_msg=str(ret), show=True, show_copy_button=True)

        try: 
            new_key = glob.glob(os.path.join(verdir, "*.der"))[0]
            shutil.move(new_key, filename)
            info_dialog(None, "Done", "Key successfully exported", show=True, show_copy_button=False)
        except IndexError: 
            return error_dialog(None, "Export failed", "Export failed.", det_msg=str(ret), show=True, show_copy_button=True)


        print(ret)



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
            shutil.copy(os.path.join(verdir, "libgourou", "AAlibgourou.so"), verdir)
            shutil.copy(os.path.join(verdir, "libgourou", "utils", "acsmdownloader"), verdir)
            shutil.copy(os.path.join(verdir, "libgourou", "utils", "adept_activate"), verdir)
            info_dialog(None, "Done", "Compiling successful", show=True, show_copy_button=False)
        except: 
            print("Can't copy ...")
            error_dialog(None, "Compiling failed", "Compiling failed. Did you install all dependencies?", det_msg=str(ret1) + "\n" + str(ret2), show=True, show_copy_button=True)
            


    def save_settings(self):
        self.deacsmprefs.set('path_to_account_data', self.txtboxUA.text())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""

