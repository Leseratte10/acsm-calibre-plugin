#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see:
https://github.com/Leseratte10/acsm-calibre-plugin
'''

'''
Lets the standalone scripts and the tests import the modules in this folder
without Calibre, as acsm_input.libadobe and so on.

Inside Calibre, this folder is the package calibre_plugins.deacsm, and its
modules import each other with relative imports (from .libadobe import ...).
Those need a package outside of Calibre, too. __init__.py can't be that
package because it needs Calibre, but Python treats every module that has
a __path__ as a package, so this module is one for this folder.
'''

import os

__path__ = [os.path.dirname(os.path.abspath(__file__))]
