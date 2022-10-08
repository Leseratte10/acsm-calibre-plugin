#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#@@CALIBRE_COMPAT_CODE@@

import sys, binascii

def GetMasterKey(wineprefix): 
    import subprocess, os, re

    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        deacsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = deacsmprefs["detailed_logging"]
    except:
        pass

    print("Asking WINE to decrypt encrypted key for us ...")
        
    if wineprefix == "" or not os.path.exists(wineprefix):
        print("Wineprefix not found!")
        return None


    # Default to win32 binary, unless we find arch in registry
    winearch = "win32"

    try: 
        system_registry_path = os.path.join(wineprefix, "system.reg")
        regfile = open(system_registry_path, "r")
        while True:
            line = regfile.readline()
            if not line:
                break

            archkey = re.match(r'#arch=(win32|win64)', line)
            if (archkey):
                winearch = archkey.groups()[0]
                break
        regfile.close()
    except:
        pass

    
    env_dict = os.environ
    env_dict["PYTHONPATH"] = ""
    env_dict["WINEPREFIX"] = wineprefix
    #env_dict["WINEDEBUG"] = "-all,+crypt"
    env_dict["WINEDEBUG"] = "+err,+fixme"

    try: 
        from calibre.utils.config import config_dir
        from calibre_plugins.deacsm.__init__ import maindir as plg_maindir
        
        if plg_maindir is not None: 
            print("FOUND MOD DIR!")
            moddir = os.path.join(plg_maindir,"modules")
        else: 
            pluginsdir = os.path.join(config_dir,"plugins")
            maindir = os.path.join(pluginsdir,"ACSMInput")
            moddir = os.path.join(maindir,"modules")
    except: 
        import os
        moddir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keyextract")

    # calls decrypt_win32.exe or decrypt_win64.exe
    proc = subprocess.Popen(["wine", "decrypt_" + winearch + ".exe"], shell=False, cwd=moddir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prog_stdout, prog_stderr = proc.communicate()

    if verbose_logging:
        print("Stderr log:\n{}".format(prog_stderr.decode("utf-8")))
        print("Stdout log: {}".format(prog_stdout.decode("utf-8")))
        print("Exit code: {}".format(proc.returncode))

    if proc.returncode == 0:
        if verbose_logging:
            print("Successfully got encryption key from WINE: {}".format(prog_stdout.decode("utf-8")))
        else:
            print("Successfully got encryption key from WINE.")
        master_key = binascii.unhexlify(prog_stdout)
        return master_key
    else: 
        print("Failed to extract encryption key from WINE.")
        print("Exit code: {}".format(proc.returncode))


        return None


if __name__ == "__main__":
    print("Do not execute this directly!")
    exit()
