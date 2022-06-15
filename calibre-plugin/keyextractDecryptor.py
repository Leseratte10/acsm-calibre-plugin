
# NOTE: 
# This file contains the two Windows executables "decrypt_win32.exe" and "decrypt_win64.exe"
# in base64-encoded form. The source code for these files can be found inside the main.c file
# in the "keyextract" directory. It's only ~200 lines of harmless C source code.

# These two programs are used only for Linux-based OSes, in order to run them in a WINE 
# environment to extract ADE account data from an ADE instance running in WINE. 

# Because these programs are decrypting data that belongs to another program (account data
# from ADE), various antivirus programs might detect them as malicious and try to block the
# plugin. As these executables aren't needed on Windows and MacOS (only on Linux), they 
# are included here in obfuscated form and are only extracted when on Linux. This should make
# antivirus programs shut up and stop reporting this plugin as a virus. 

import base64

def get_win32_data(): 
    return base64.b64decode(data_win32)

def get_win64_data(): 
    return base64.b64decode(data_win64)


data_win32 = """
@@@CALIBRE_DECRYPTOR_WIN32_B64@@@
"""

data_win64 = """
@@@CALIBRE_DECRYPTOR_WIN64_B64@@@
"""
