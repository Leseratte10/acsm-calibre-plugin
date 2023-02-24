'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

from lxml import etree
import base64
import os, locale, platform

try: 
    from Cryptodome.Cipher import AES as _AES
except ImportError:
    # Some distros still ship this as Crypto
    from Crypto.Cipher import AES as _AES


#@@CALIBRE_COMPAT_CODE@@


class AES(object):
    def __init__(self, key, iv):
        self._aes = _AES.new(key, _AES.MODE_CBC, iv)
    def decrypt(self, data):
        return self._aes.decrypt(data)


from libadobe import makeSerial, get_devkey_path, get_device_path, get_activation_xml_path
from libadobe import VAR_VER_HOBBES_VERSIONS, VAR_VER_OS_IDENTIFIERS, VAR_VER_DEFAULT_BUILD_ID, VAR_VER_BUILD_IDS


def importADEactivationLinuxWine(wine_prefix_path, buildIDtoEmulate=VAR_VER_DEFAULT_BUILD_ID):
    # Similar to importADEactivationWindows - extracts the activation data from a Wine prefix
    try:
        from calibre.constants import islinux
        if not islinux:
            print("This function is for Linux only!")
            return False, "Linux only!"
    except:
        pass

    # Get encryption key
    from getEncryptionKeyLinux import GetMasterKey

    master_key = GetMasterKey(wine_prefix_path)

    if master_key is None:
        err = "Could not access ADE encryption key. If you have just installed ADE in Wine, "
        err += "please reboot your machine then try again. Also, make sure neither ADE nor any other "
        err += "software is running in WINE while you're trying to import the authorization. "
        err += "If it still doesn't work but ADE in that particular WINEPREFIX is working fine, "
        err += "please open a bug report."

        return False, err

    # Loop through the registry:
    try: 
        registry_file = open(os.path.join(wine_prefix_path, "user.reg"), "r")
        waiting_for_element = False
        current_parent = None
        current_name = None
        current_value = None
        current_method = None
        while True: 
            line = registry_file.readline()
            if not line:
                break
            line = line.strip()

            if waiting_for_element:
                if (line.lower().startswith("@=")): 
                    current_name = line.split('=', 1)[1].strip()[1:-1]
                    continue
                
                if (line.lower().startswith('"value"=')): 
                    current_value = line.split('=', 1)[1].strip()[1:-1]
                    continue
            
                if (line.lower().startswith('"method"=')): 
                    current_method = line.split('=', 1)[1].strip()[1:-1]
                    continue

                if (len(line) == 0):
                    # Empty line - finalize this element
                    if current_value is None:
                        current_parent = current_name
                        current_name = None
                        current_method = None
                        current_value = None
                        waiting_for_element = False
                        continue
                    handle_subkey(current_parent, current_name, current_value, master_key, current_method, None)
                    current_name = None
                    current_value = None
                    current_method = None


            else: 
                if (line.startswith("[Software\\\\Adobe\\\\Adept\\\\Activation\\\\")):
                    waiting_for_element = True

                                
        registry_file.close()
        return handle_subkey(None, None, None, master_key, None, buildIDtoEmulate)

    except: 
        # There was an error hunting through the registry. 
        raise
        pass

def importADEactivationWindows(buildIDtoEmulate=VAR_VER_DEFAULT_BUILD_ID):
    # Tries to import the system activation from Adobe Digital Editions on Windows into the plugin
    # This can be used to "clone" the ADE activation so you don't need to waste an additional activation.

    try: 
        from calibre.constants import iswindows
    except:
        import sys
        iswindows = sys.platform.startswith('win')

    if not iswindows:
        print("This function is for Windows only!")
        return False, "Windows only!"

    # Get encryption key:
    from getEncryptionKeyWindows import GetMasterKey

    master_key = GetMasterKey()

    if master_key is None: 
        return False, "Could not access ADE encryption key"

    PRIVATE_LICENCE_KEY_PATH = r'Software\Adobe\Adept\Activation'

    # Dump data from registry:
    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    try: 
        activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PRIVATE_LICENCE_KEY_PATH)
    except: 
        return False, "Could not locate ADE activation"

    i = 0
    while True:
        try: 
            activation_parent = winreg.OpenKey(activation_root, "%04d" % (i))
        except: 
            break

        ParentKeyType = winreg.QueryValueEx(activation_parent, None)[0]
        j = 0
        while True:
            try: 
                activation_child = winreg.OpenKey(activation_parent, "%04d" % (j))
            except:
                break

            SubKeyType = winreg.QueryValueEx(activation_child, None)[0]
            try: 
                value = winreg.QueryValueEx(activation_child, 'value')[0]
                try: 
                    method = winreg.QueryValueEx(activation_child, 'method')[0]
                except:
                    method = None

                handle_subkey(ParentKeyType, SubKeyType, value, master_key, method, None)
            except:
                pass

            j = j + 1
        
        i = i + 1

    return handle_subkey(None, None, None, master_key, None, buildIDtoEmulate)

persistent_data = dict()
account_method = None

def finalize_write_config_Windows(data, key, buildID):
    # Okay, finally got all the data that's needed - recreate all the files.

     # Create devicekey file:
    f = open(get_devkey_path(), "wb")
    f.write(key)
    f.close()

    # Create activation.xml
    f = open(get_activation_xml_path(), "w")

    content = '<?xml version="1.0"?>\n'
    content += "<activationInfo xmlns=\"http://ns.adobe.com/adept\">\n"
    content += '<adept:activationServiceInfo xmlns:adept="http://ns.adobe.com/adept">\n'

    content += "<adept:authURL>%s</adept:authURL>" % (data["activationServiceInfo"]["authURL"])
    content += "<adept:userInfoURL>%s</adept:userInfoURL>" % (data["activationServiceInfo"]["userInfoURL"])
    content += "<adept:activationURL>%s</adept:activationURL>" % (data["activationServiceInfo"]["activationURL"])
    content += "<adept:certificate>%s</adept:certificate>" % (data["activationServiceInfo"]["certificate"])
    content += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (data["activationServiceInfo"]["authenticationCertificate"])
    content += '</adept:activationServiceInfo>\n'

    content += '<adept:credentials xmlns:adept="http://ns.adobe.com/adept">'
    content += "<adept:user>%s</adept:user>" % (data["credentials"]["user"])
    global account_method
    if "username" in data["credentials"]:
        if account_method is None:
            account_method = "AdobeID"
    
        content += "<adept:username method=\"%s\">%s</adept:username>" % (account_method, data["credentials"]["username"])
    
    content += "<adept:pkcs12>%s</adept:pkcs12>" % (data["credentials"]["pkcs12"])
    content += "<adept:licenseCertificate>%s</adept:licenseCertificate>" % (data["credentials"]["licenseCertificate"])
    content += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>" % (data["credentials"]["privateLicenseKey"])
    content += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (data["credentials"]["authenticationCertificate"])
    content += '</adept:credentials>\n'

    content += '<activationToken xmlns="http://ns.adobe.com/adept">'

    for x in ["device", "fingerprint", "deviceType", "activationURL", "user", "signature"]:
        content += "<%s>%s</%s>" % (x, data["activationToken"][x], x)

    content += '</activationToken>\n'
    content += '</activationInfo>\n'

    f.write(content)
    f.close()

    # Re-create device.xml from scratch:

    content = '<?xml version="1.0"?>\n'
    content += '<adept:deviceInfo xmlns:adept="http://ns.adobe.com/adept">\n'
    content += "<adept:deviceType>%s</adept:deviceType>\n" % (data["activationToken"]["deviceType"])
    content += "<adept:deviceClass>%s</adept:deviceClass>\n" % ("Desktop")
    content += "<adept:deviceSerial>%s</adept:deviceSerial>\n" % (makeSerial(False))
    content += "<adept:deviceName>%s</adept:deviceName>\n" % (platform.uname()[1])

    version_idx = VAR_VER_BUILD_IDS.index(buildID)
    hobbes_ver = VAR_VER_HOBBES_VERSIONS[version_idx]
    clientOS = VAR_VER_OS_IDENTIFIERS[version_idx]

    content += "<adept:version name=\"hobbes\" value=\"%s\"/>\n" % (hobbes_ver)
    content += "<adept:version name=\"clientOS\" value=\"%s\"/>\n" % (clientOS)

    language = None
    try: 
        language = locale.getdefaultlocale()[0].split('_')[0]
    except:
        pass
    if language is None or language == "": 
        # Can sometimes happen on MacOS with default English language
        language = "en"

    content += "<adept:version name=\"clientLocale\" value=\"%s\"/>\n" % (language)
    content += "<adept:fingerprint>%s</adept:fingerprint>\n" % (data["activationToken"]["fingerprint"])
    content += "</adept:deviceInfo>"

    # Write device.xml
    f = open(get_device_path(), "w")
    f.write(content)
    f.close()


    return True, "Done"

def handle_subkey(parent, subkey, value, encryption_key, method, buildID):

    if parent is None: 
        # We're done collecting sub keys - decrypt the private key, then finalize config.
        # The first 16 bytes of the fingerprint are used as IV for the privateLicenseKey
        # Older versions of this decryption code, like in the DeDRM plugin, didn't 
        # do that correctly. For DeDRM that doesn't matter as a wrong IV only causes
        # the first 16 bytes to be corrupted, and these aren't used for eBook decryption anyways.
        # For this plugin I want the exact correct data, so lets use the fingerprint as IV.
        # See jhowell's post: https://www.mobileread.com/forums/showpost.php?p=4173908

        iv = persistent_data["activationToken"]["fingerprint"]
        iv = base64.b64decode(iv)[:16]
        aes = AES(encryption_key, iv)

        value = base64.b64decode(persistent_data["credentials"]["privateLicenseKey"])
        persistent_data["credentials"]["privateLicenseKey"] = base64.b64encode(aes.decrypt(value)).decode("latin-1")

        return finalize_write_config_Windows(persistent_data, encryption_key, buildID)
    else: 
        # collecting a single sub key by storing it in the global list "persistent_data"
        global account_method
        if method:
            account_method = method

        # Not encrypted
        try: 
            persistent_data[parent][subkey] = value
        except KeyError:
            persistent_data[parent] = dict()
            persistent_data[parent][subkey] = value

    return None

def getMacCredential(type):

    import os, re

    # Just calling a native binary.
    # The python modules were all A) pretty complicated and B) are only intended
    # to read your own credentials, so they require the user to manually add
    # Python to the list of applications allowed to read ADE credentials.
    # By calling this "security" binary, it will instead pop up a password input
    # dialog, having the user verify that they do want to export the ADE keys.
    
    cmd = ' '.join([
        "/usr/bin/security", 
        "find-generic-password", 
        "-g -s '%s' -a '%s'" % ("Digital Editions", type), 
        "2>&1 >/dev/null"
    ])

    p = os.popen(cmd)
    s = p.read()
    p.close()

    m = re.match(r"password: (?:0x([0-9A-F]+)\s*)?\"(.*)\"$", s)
    if m:
        hexform, stringform = m.groups()
        if hexform:
            return bytes.fromhex(hexform)
        else:
            return bytes(stringform, 'latin-1')
        
    return None


def importADEactivationMac(buildIDtoEmulate=VAR_VER_DEFAULT_BUILD_ID):
    # Tries to import the system activation from Adobe Digital Editions on a Mac into the plugin
    # This can be used to "clone" the ADE activation so you don't need to waste an additional activation.

    import sys

    try: 
        from calibre.constants import isosx
    except:
        isosx = sys.platform.startswith('darwin')

    if not isosx:
        print("This function is for MacOS only!")
        return False, "MacOS only!"

    import subprocess
    import warnings
    warnings.filterwarnings('ignore', category=FutureWarning)

    home = os.getenv('HOME')
    cmdline = 'find "' + home + '/Library/Application Support/Adobe/Digital Editions" -name "activation.dat"'
    cmdline = cmdline.encode(sys.getfilesystemencoding())
    p2 = subprocess.Popen(cmdline, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=False)
    out1, out2 = p2.communicate()
    reslst = out1.split(b'\n')
    cnt = len(reslst)
    ActDatPath = b"activation.dat"
    for j in range(cnt):
        resline = reslst[j]
        pp = resline.find(b'activation.dat')
        if pp >= 0:
            ActDatPath = resline
            break

    
    if not os.path.exists(ActDatPath):
        print("Activation file does not exist ...")
        return False, "Activation file not found"


    # activation.xml is at ActDatPath.
    # Now get the password(s) ...

    DeviceKey = getMacCredential("DeviceKey")
    DeviceFingerprint = getMacCredential("DeviceFingerprint")

    if (DeviceKey is None or DeviceFingerprint is None):
        print("There was an error exporting the keys from the MacOS keychain.")
        return False, "Error while exporting keys"

    return recreateMacActivationFiles(ActDatPath, DeviceKey, DeviceFingerprint, buildIDtoEmulate)

def recreateMacActivationFiles(path_to_activation, deviceKey, deviceFingerprint, buildIDtoEmulate):

    if (len(deviceKey) != 16):
        print("Looks like the device key is invalid ...")
        return False, "Invalid device key"
    
    # Create activation.xml file:
    import shutil
    shutil.copyfile(path_to_activation, get_activation_xml_path())

    # Create devicekey file:
    f = open(get_devkey_path(), "wb")
    f.write(deviceKey)
    f.close()

    # Read and parse activation.xml
    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    devtype = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("deviceType"))).text


    # Re-create device.xml from scratch:

    content = '<?xml version="1.0"?>\n'
    content += '<adept:deviceInfo xmlns:adept="http://ns.adobe.com/adept">\n'
    content += "<adept:deviceType>%s</adept:deviceType>\n" % (devtype)
    content += "<adept:deviceClass>%s</adept:deviceClass>\n" % ("Desktop")
    content += "<adept:deviceSerial>%s</adept:deviceSerial>\n" % (makeSerial(False))
    content += "<adept:deviceName>%s</adept:deviceName>\n" % (platform.uname()[1])

    version_idx = VAR_VER_BUILD_IDS.index(buildIDtoEmulate)
    hobbes_ver = VAR_VER_HOBBES_VERSIONS[version_idx]
    clientOS = VAR_VER_OS_IDENTIFIERS[version_idx]

    content += "<adept:version name=\"hobbes\" value=\"%s\"/>\n" % (hobbes_ver)
    content += "<adept:version name=\"clientOS\" value=\"%s\"/>\n" % (clientOS)

    language = None
    try: 
        language = locale.getdefaultlocale()[0].split('_')[0]
    except:
        pass
    if language is None or language == "": 
        # Can sometimes happen on MacOS with default English language
        language = "en"

    content += "<adept:version name=\"clientLocale\" value=\"%s\"/>\n" % (language)
    content += "<adept:fingerprint>%s</adept:fingerprint>\n" % (base64.b64encode(deviceFingerprint))
    content += "</adept:deviceInfo>"

    # Write device.xml
    f = open(get_device_path(), "w")
    f.write(content)
    f.close()

    return True, "Success"