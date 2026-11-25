#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import binascii, traceback

# How long the key helper may run in WINE. Starting WINE can take half a minute or more when
# it updates the prefix, and it may show dialogs that wait for the user. But Calibre waits for
# the helper on its GUI thread, so a WINE that hangs must not freeze it forever.
WINE_TIMEOUT = 120      # seconds

def GetMasterKey(wineprefix, use_bytebooks = None):
    # use_bytebooks: True / False makes the helper decrypt the ByteBooks / Adobe device key,
    # so it matches the activation that's being imported. None keeps the old behaviour
    # (ByteBooks if BDE has a device key, otherwise Adobe).
    # Returns the 16-byte device key, or None if that fails. It never raises, so that the
    # import can show its error message instead of a traceback.
    try:
        return _get_master_key(wineprefix, use_bytebooks)
    except Exception:
        print("Failed to extract encryption key from WINE:")
        traceback.print_exc()
        return None

def _get_master_key(wineprefix, use_bytebooks):
    import subprocess, os, re, shutil, tempfile, time

    verbose_logging = False
    try: 
        from . import prefs
        acsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = acsmprefs["detailed_logging"]
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

    
    env_dict = os.environ.copy()
    env_dict["PYTHONPATH"] = ""
    env_dict["WINEPREFIX"] = wineprefix
    #env_dict["WINEDEBUG"] = "-all,+crypt"
    env_dict["WINEDEBUG"] = "+err,+fixme"

    # The helper goes into a new temporary folder, which is deleted again once Wine has run it.
    helper_dir = tempfile.mkdtemp(prefix="acsm_input_")

    # extract the EXE file from Python code:
    # EXE files are obfuscated with base64 so that stupid AV programs
    # don't flag this whole plugin as malicious. 
    # See keyextractDecryptor.py and the folder "keyextract" for more information.

    try: 
        print("Extracting WINE key tools ...")
        from .keyextractDecryptor import get_win32_data, get_win64_data

        if winearch == "win32":
            file32 = os.path.join(helper_dir, "decrypt_win32.exe")
            f = open(file32, "wb")
            f.write(get_win32_data())
            f.close()

        elif winearch == "win64":
            file64 = os.path.join(helper_dir, "decrypt_win64.exe")
            f = open(file64, "wb")
            f.write(get_win64_data())   
            f.close()
        
        else: 
            print("Invalid winearch: " + str(winearch))
            
    except:
        print("Error while extracting packed WINE ADE key extraction EXE files ")
        traceback.print_exc()

    # calls decrypt_win32.exe or decrypt_win64.exe
    helper_cmd = ["wine", "decrypt_" + winearch + ".exe"]
    if use_bytebooks is not None:
        helper_cmd.append("bytebooks" if use_bytebooks else "adobe")

    try:
        # The output goes to temporary files instead of pipes, so waiting for the helper can't
        # block on them: a full pipe stalls the helper, and processes that WINE starts in the
        # background can keep a pipe open after the helper has exited.
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            try:
                proc = subprocess.Popen(helper_cmd, shell=False, cwd=helper_dir, stdout=stdout_file, stderr=stderr_file, env=env_dict)
            except OSError as e:
                # Usually because wine isn't installed, or Calibre can't see it (as in a Flatpak)
                print("Failed to run WINE: {}".format(e))
                return None

            # Popen.communicate() and wait() have no timeout on Python 2
            deadline = time.time() + WINE_TIMEOUT
            while proc.poll() is None:
                if time.time() > deadline:
                    print("WINE didn't finish within {} seconds, giving up.".format(WINE_TIMEOUT))
                    proc.kill()
                    proc.wait()
                    return None
                time.sleep(0.1)

            stdout_file.seek(0)
            prog_stdout = stdout_file.read()
            stderr_file.seek(0)
            prog_stderr = stderr_file.read()
    finally:
        shutil.rmtree(helper_dir, ignore_errors=True)

    if verbose_logging:
        print("Stderr log:\n{}".format(prog_stderr.decode("utf-8", "replace")))
        print("Stdout log: {}".format(prog_stdout.decode("utf-8", "replace")))
        print("Exit code: {}".format(proc.returncode))

    if proc.returncode != 0:
        print("Failed to extract encryption key from WINE.")
        print("Exit code: {}".format(proc.returncode))
        return None

    # The helper prints the 16-byte device key as 32 hex digits. Check that instead of
    # relying on the exit code alone.
    master_key = None
    try:
        master_key = binascii.unhexlify(prog_stdout.strip())
    except (TypeError, ValueError):
        pass

    if master_key is None or len(master_key) != 16:
        print("Failed to extract encryption key from WINE: the helper didn't print a 16-byte key.")
        return None

    if verbose_logging:
        print("Successfully got encryption key from WINE: {}".format(prog_stdout.decode("utf-8", "replace")))
    else:
        print("Successfully got encryption key from WINE.")
    return master_key


if __name__ == "__main__":
    print("Do not execute this directly!")
    exit()
