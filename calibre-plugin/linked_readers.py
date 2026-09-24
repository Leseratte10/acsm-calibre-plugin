#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2024 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see:
https://github.com/Leseratte10/acsm-calibre-plugin
'''

# Keeping the loan data of eReaders authorized through USB up to date.

#@@CALIBRE_COMPAT_CODE@@

import os
from lxml import etree

import calibre_plugins.deacsm.prefs as prefs    # type: ignore


adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)


def find_adobe_folder(path):
    # Accepts the reader's root folder or any folder on it, like "Authorize eReader over USB".
    for i in range(15):
        adobe_path = os.path.join(path, ".adobe-digital-editions")
        if os.path.isdir(adobe_path):
            return adobe_path

        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent

    return None


def get_reader_authorization(adobe_path):
    # Returns (user, device) of the reader's Adobe authorization, or (None, None).
    try:
        act = etree.parse(os.path.join(adobe_path, "activation.xml"))
        user = act.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
        device = act.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text
        return user, device
    except:
        return None, None


def refresh_reader(adobe_path):
    from libadobe import update_account_path
    from libadobeAccount import refreshLoanTokensOnDevice

    update_account_path(prefs.ACSMInput_Prefs()["path_to_account_data"])
    return refreshLoanTokensOnDevice(os.path.join(adobe_path, "activation.xml"))
