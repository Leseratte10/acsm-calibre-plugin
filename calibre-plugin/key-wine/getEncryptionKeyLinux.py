#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def unfuck(user):
    # Wine uses a pretty nonstandard encoding in their registry file. 
    # I haven't found any existing Python implementation for that,
    # so I looked at the C code and wrote my own. 
    # This implementation doesn't support multi-byte UTF-8 chars,
    # but a standard-conforming Wine registry won't contain 
    # these anyways, so who cares. 

    hex_char_list = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 97, 98, 99, 100, 101, 102]

    # Remove the quotation marks at beginning and end:
    user = user.strip()[1:-1]
    user_new = bytearray()
    i = 0
    while i < len(user):
        # Convert string of len 1 to a byte
        char = user[i][0].encode("latin-1")[0]
        if char == ord('\\'):
            # Get next char:
            i += 1
            char = user[i][0].encode("latin-1")[0]
            if (char == ord('a')):
                user_new.append(0x07)
            elif (char == ord('b')):
                user_new.append(0x08)
            elif (char == ord('e')):
                user_new.append(0x1b)
            elif (char == ord('f')):
                user_new.append(0x0c)
            elif (char == ord('n')):
                user_new.append(0x0a)
            elif (char == ord('r')):
                user_new.append(0x0d)
            elif (char == ord('t')):
                user_new.append(0x09)
            elif (char == ord('v')):
                user_new.append(0x0b)
            elif (char == ord('x')):
                # Get next char
                i += 1
                char = user[i][0].encode("latin-1")[0]
                if char not in hex_char_list:
                    user_new.append(ord('x'))
                    # This seems to be fallback code. 
                    # Probably a bug in wine: We should also add "char" - but Wine doesn't either ...
                else: 
                    ival = "" + chr(char)
                    
                    # Read up to 3 more chars
                    next = user[i + 1][0].encode("latin-1")[0]
                    if next in hex_char_list:
                        ival += chr(next)
                        i += 1
                    
                    next = user[i + 1][0].encode("latin-1")[0]
                    if next in hex_char_list:
                        ival += chr(next)
                        i += 1
                    
                    next = user[i + 1][0].encode("latin-1")[0]
                    if next in hex_char_list:
                        ival += chr(next)
                        i += 1

                    # ival now contains "00e9". Convert to int ...
                    ival = int(ival, 16)
                    # then drop everything except the lowest byte
                    ival = ival & 0xFF
                    # then add it to the array
                    user_new.append(ival)
            elif (char >= ord('0') and char <= ord('9') ):

                octal = char - ord('0')

                # Read up to 2 more chars
                next = user[i + 1][0].encode("latin-1")[0]
                if next >= ord('0') and next <= ord('9'):
                    octal = (octal * 8) + (next - ord('0'))
                    i += 1
                
                next = user[i + 1][0].encode("latin-1")[0]
                if next >= ord('0') and next <= ord('9'):
                    octal = (octal * 8) + (next - ord('0'))
                    i += 1

        else: 

            if (char < 0x80):
                user_new.append(char)
            else:
                print("Multi-Byte UTF-8, not supported")
                print("This should never happen in a standard-conform Wine registry ...")
                return False

        # Parse next char
        i += 1

    return user_new

def GetMasterKey(path_to_wine_prefix): 

    import os

    if os.name == 'nt':
        print("Hey! This is for Linux!")
        return

    import cpuid
    import struct

    try: 
        # Linux / Wine code just assumes that the system drive is C:\
        serial_file = open(os.path.join(path_to_wine_prefix, "drive_c", ".windows-serial"), "r")
        serial = serial_file.read()
        serial_file.close()
        serial = int(serial, 16)
    except:
        # If this file is not present, Wine will use a default serial number of "0". 
        serial = 0

    print("Serial: " + str(serial))
    
    cpu = cpuid.CPUID()
    _, b, c, d = cpu(0)
    vendor = struct.pack("III", b, d, c)

    print("Vendor: " + vendor.decode("utf-8"))

    signature, _, _, _ = cpu(1)
    signature = struct.pack('>I', signature)[1:]

    print("Signature: " + str(signature.hex()))

    # Search for the username in the registry:
    user = None
    

    # Linux - loop through the Wine registry file to find the "username" attribute
    try: 
        registry_file = open(os.path.join(path_to_wine_prefix, "user.reg"))
        waiting_for_username = False
        while True: 
            line = registry_file.readline()
            if not line:
                break

            if waiting_for_username:
                if (not line.lower().startswith("\"username\"=")): 
                    continue
                
                # If we end up here, we have the username.
                user = line.split('=', 1)[1].strip()
                user = unfuck(user)
                break

            else: 
                if (line.startswith("[Software\\\\Adobe\\\\Adept\\\\Device]")):
                    waiting_for_username = True
                
                if (line.startswith("[Volatile Environment]")):
                    waiting_for_username = True
                
        registry_file.close()
    except: 
        # There was an error hunting through the registry. 
        raise
        pass

    if (user is None):
        print("Error while determining username ...")
        exit()

    print("Username: " + str(user))

    # Find the value we want to decrypt from the registry. loop through the Wine registry file to find the "key" attribute
    try: 
        registry_file = open(os.path.join(path_to_wine_prefix, "user.reg"))
        waiting_for_key = False
        key_line = None
        while True: 
            line = registry_file.readline()
            if not line:
                break

            if waiting_for_key:
                if (not line.lower().startswith("\"key\"=")): 
                    continue
                
                # If we end up here, we have the key.
                key_line = line
                while (key_line.strip().endswith('\\')):
                    key_line = key_line.strip()[:-1] + registry_file.readline()

                # Now parse ...
                key_line = key_line.split(':', 1)[1]
                key_line = key_line.replace('\t', '').replace(' ', '').replace(',', '')
                key_line = bytes.fromhex(key_line)

            else: 
                if (line.startswith("[Software\\\\Adobe\\\\Adept\\\\Device]")):
                    waiting_for_key = True
                
                
                

        registry_file.close()
    except: 
        # There was an error hunting through the registry. 
        raise
        pass


    print("Encrypted key: " + str(key_line))

    import hexdump

    hexdump.hexdump(key_line)

    # These should all be "bytes" or "bytearray"
    #print(type(vendor))
    #print(type(signature))
    #print(type(user))

    entropy = struct.pack('>I12s3s13s', serial, vendor, signature, user)

    print("Entropy: " + str(entropy))

    # We would now call CryptUnprotectData to decrypt the stuff, 
    # but unfortunately there's no working Linux implementation 
    # for that. This means we have to call a Windows binary through
    # Wine just for this one single decryption call ...

    success, data = CryptUnprotectDataExecuteWine(path_to_wine_prefix, key_line, entropy)
    if (success):
        keykey = data
        print(keykey)
        return keykey
    
    else: 
        print("Error number: " + str(data))
        if data == 13: # WINError ERROR_INVALID_DATA
            print("Could not decrypt data with the given key. Did the Wine username change?")
        return None


def CryptUnprotectDataExecuteWine(wineprefix, data, entropy):
    import subprocess, os, re

    print("Asking WINE to decrypt encrypted key for us ...")
        
    if wineprefix == "" or not os.path.exists(wineprefix):
        print("Wineprefix not found!!")
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

            stuff = re.match(r'#arch=(win32|win64)', line)
            if (stuff):
                winearch = stuff.groups()[0]
                break
        regfile.close()
    except:
        pass

    
    # Execute!

    env_dict = os.environ
    env_dict["PYTHONPATH"] = ""
    env_dict["WINEPREFIX"] = wineprefix
    env_dict["WINEDEBUG"] = "-all,+crypt"

    import base64

    env_dict["X_DECRYPT_DATA"] = data.hex()
    env_dict["X_DECRYPT_ENTROPY"] = entropy.hex()

    try: 
        from calibre.utils.config import config_dir
        pluginsdir = os.path.join(config_dir,"plugins")
        maindir = os.path.join(pluginsdir,"DeACSM")
        moddir = os.path.join(maindir,"modules")
    except: 
        import os
        moddir = os.path.dirname(os.path.abspath(__file__))

    proc = subprocess.Popen(["wine", "decrypt_" + winearch + ".exe" ], shell=False, cwd=moddir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prog_output, prog_stderr = proc.communicate()
    # calls decrypt_win32.exe or decrypt_win64.exe


    if prog_output.decode("utf-8").startswith("PROGOUTPUT:0:"):
        key_string = prog_output.decode("utf-8").split(':')[2]
        print("Successfully got encryption key from WINE: " + key_string)
        master_key = bytes.fromhex(key_string)
        return True, master_key

        
    else: 
        print("Huh. That didn't work. ")
        err = int(prog_output.decode("utf-8").split(':')[1])
        if err == -4:
            err = int(prog_output.decode("utf-8").split(':')[2])

        print("Program reported: " + prog_output.decode("utf-8"))
        print("Debug log: ")
        print(prog_stderr.decode("utf-8"))
        return False, err



GetMasterKey()
