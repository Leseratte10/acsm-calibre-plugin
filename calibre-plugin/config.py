#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyright: reportUndefinedVariable=false


from PyQt5.Qt import (Qt, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QLineEdit,
                      QGroupBox, QPushButton, QListWidget, QListWidgetItem,
                      QAbstractItemView, QIcon, QDialog, QDialogButtonBox, QUrl)

from PyQt5 import Qt as QtGui
from zipfile import ZipFile

# calibre modules and constants.
from calibre.gui2 import (question_dialog, info_dialog)                     # type: ignore
# modules from this plugin's zipfile.
from calibre_plugins.deacsm.__init__ import PLUGIN_NAME, PLUGIN_VERSION      # type: ignore
import calibre_plugins.deacsm.prefs as prefs                                 # type: ignore


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


        ua_group_box = QGroupBox(_('Path to account:'), self)
        layout.addWidget(ua_group_box)
        ua_group_box_layout = QVBoxLayout()
        ua_group_box.setLayout(ua_group_box_layout)

        self.txtboxUA = QtGui.QLineEdit(self)
        self.txtboxUA.setToolTip(_("Enter folder path to account data"))
        self.txtboxUA.setText(self.tempdeacsmprefs['path_to_account_data'])
        ua_group_box_layout.addWidget(self.txtboxUA)


        self.resize(self.sizeHint())


    def save_settings(self):
        self.deacsmprefs.set('path_to_account_data', self.txtboxUA.text())
        self.deacsmprefs.writeprefs()

    def load_resource(self, name):
        with ZipFile(self.plugin_path, 'r') as zf:
            if name in zf.namelist():
                return zf.read(name).decode('utf-8')
        return ""

