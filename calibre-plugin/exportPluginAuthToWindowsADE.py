#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Takes an existing Adobe authorization in the plugin, 
# writes that into the Windows registry so ADE can read and use it.

# In progress ...

try:
    from ctypes import windll
except ImportError:
    import os
    if os.name != 'nt':
        print("This script is for Windows!")
        exit()
    else:
        raise

def GetSystemDirectory():
    from ctypes import windll, c_wchar_p, c_uint, create_unicode_buffer
    MAX_PATH = 255

    kernel32 = windll.kernel32
    GetSystemDirectoryW = kernel32.GetSystemDirectoryW
    GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint]
    GetSystemDirectoryW.restype = c_uint

    buffer = create_unicode_buffer(MAX_PATH + 1)
    GetSystemDirectoryW(buffer, len(buffer))
    return buffer.value


def GetVolumeSerialNumber(path):
    from ctypes import windll, c_wchar_p, c_uint, POINTER, byref

    kernel32 = windll.kernel32
    GetVolumeInformationW = kernel32.GetVolumeInformationW
    GetVolumeInformationW.argtypes = [c_wchar_p, c_wchar_p, c_uint,
                                        POINTER(c_uint), POINTER(c_uint),
                                        POINTER(c_uint), c_wchar_p, c_uint]
    GetVolumeInformationW.restype = c_uint
    vsn = c_uint(0)
    GetVolumeInformationW(
        path, None, 0, byref(vsn), None, None, None, 0)
    return vsn.value



def GetUserNameWINAPI():
    from ctypes import windll, c_wchar_p, c_uint, POINTER, byref, create_unicode_buffer
    advapi32 = windll.advapi32
    GetUserNameW = advapi32.GetUserNameW
    GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
    GetUserNameW.restype = c_uint

    buffer = create_unicode_buffer(32)
    size = c_uint(len(buffer))
    while not GetUserNameW(buffer, byref(size)):
        buffer = create_unicode_buffer(len(buffer) * 2)
        size.value = len(buffer)
    
    # Yes, it's actually implemented like that. Encode in UTF16 but only take the lowest byte of each character.
    return buffer.value.encode('utf-16-le')[::2]


from ctypes import Structure, c_uint, c_void_p, POINTER
class DataBlob(Structure):
    _fields_ = [('cbData', c_uint),
                ('pbData', c_void_p)]
DataBlob_p = POINTER(DataBlob)

def CryptProtectData(indata, entropy):

    # TODO: description needs to be "deviceKey"

    from ctypes import windll, c_wchar_p, c_uint, byref, cast, create_string_buffer, string_at

    crypt32 = windll.crypt32
    _CryptProtectData = crypt32.CryptProtectData
    _CryptProtectData.argtypes = [DataBlob_p, c_wchar_p, DataBlob_p,
                                c_void_p, c_void_p, c_uint, DataBlob_p]
    _CryptProtectData.restype = c_uint
    indatab = create_string_buffer(indata)
    indata = DataBlob(len(indata), cast(indatab, c_void_p))
    entropyb = create_string_buffer(entropy)
    entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
    outdata = DataBlob()
    if not _CryptProtectData(byref(indata), None, byref(entropy),
                                None, None, 0, byref(outdata)):
        return None
    return string_at(outdata.pbData, outdata.cbData)


def GetMasterKey(): 

    import os

    if os.name != 'nt':
        print("This script is for Windows!")

    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        deacsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = deacsmprefs["detailed_logging"]
    except:
        pass

    # Get serial number of root drive
    root = GetSystemDirectory().split('\\')[0] + '\\'
    serial = GetVolumeSerialNumber(root)
    if verbose_logging:
        print("Serial: " + str(serial))

    
    # Get CPU vendor:
    try:
        import cpuid
    except:
        import calibre_plugins.deacsm.cpuid as cpuid

    import struct
    cpu = cpuid.CPUID()
    _, b, c, d = cpu(0)
    vendor = struct.pack("III", b, d, c)

    if verbose_logging:
        print("Vendor: " + vendor.decode("utf-8"))

    signature, _, _, _ = cpu(1)
    signature = struct.pack('>I', signature)[1:]

    if verbose_logging:
        print("Signature: " + str(signature.hex()))

    # Search for the username in the registry:
    user = None

    user_from_registry = GetUserNameREG()
    current_user_name = GetUserNameWINAPI()

    if (user_from_registry is not None):
        # Found entry
        user = user_from_registry
    else:
        user = current_user_name

    if verbose_logging:
        if (user_from_registry is not None and user_from_registry != current_user_name):
            print("Username: {0}/{1} mismatch, using {0}".format(str(user_from_registry), str(current_user_name)))
        elif (user_from_registry is not None):
            print("Username: {0} (Registry)".format(str(user_from_registry)))
        else:
            print("Username: {0} (WinAPI)".format(str(current_user_name)))



    # Find the value we want to decrypt from the registry:
    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    try: 
        DEVICE_KEY_PATH = r'Software\Adobe\Adept\Device'
        regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, DEVICE_KEY_PATH)
        device = winreg.QueryValueEx(regkey, 'key')[0]
    except: 
        print("Can't find encrypted device key.")
        return None

    if verbose_logging:
        print("Encrypted key: " + str(device))

    # These three must all be bytes.
    #print(type(vendor))
    #print(type(signature))
    #print(type(user))

    entropy = struct.pack('>I12s3s13s', serial, vendor, signature, user)

    if verbose_logging:
        print("Entropy: " + str(entropy))

    keykey = CryptUnprotectData(device, entropy)
    if (keykey is None):
        print("Couldn't decrypt key!")
        return None

    if verbose_logging:
        print("Decrypted key: " + str(keykey))
        
    return keykey


if __name__ == "__main__":
    GetMasterKey()
