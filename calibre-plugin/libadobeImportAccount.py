'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''


# TODO: This still needs to be adapted for ByteBooks

from lxml import etree
import base64
import os, locale, platform
from xml.sax.saxutils import escape as xml_escape


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
        current_ofbytebooks = None
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

                if (line.lower().startswith('"ofbytebooks"=')): 
                    val = line.split('=', 1)[1].strip()[1:-1]
                    if val == "1" or val.lower() == "true" or val == True:
                        current_ofbytebooks = True
                    elif val == "0" or val.lower() == "false" or val == False:
                        current_ofbytebooks = False
                    else:
                        print("Warning: Invalid ofByteBooks value while importing.")
                        current_ofbytebooks = False
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
                        current_ofbytebooks = None
                        current_value = None
                        waiting_for_element = False
                        continue
                    handle_subkey(current_parent, current_name, current_value, master_key, current_method, current_ofbytebooks, None)
                    current_name = None
                    current_value = None
                    current_ofbytebooks = None
                    current_method = None


            else: 
                if (line.startswith("[Software\\\\Adobe\\\\Adept\\\\Activation\\\\")):
                    waiting_for_element = True
                if (line.startswith("[Software\\\\ByteBooks\\\\Adept\\\\Activation\\\\")):
                    waiting_for_element = True

                                
        registry_file.close()
        return handle_subkey(None, None, None, master_key, None, None, buildIDtoEmulate)

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

    # Dump data from registry:
    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    try: 
        activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\ByteBooks\Adept\Activation')
    except: 
        try: 
            activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Adobe\Adept\Activation')
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
                try: 
                    val = winreg.QueryValueEx(activation_child, 'ofByteBooks')[0]
                    if val == "1" or val.lower() == "true" or val == True:
                        ofbytebooks = True
                    elif val == "0" or val.lower() == "false" or val == False:
                        ofbytebooks = False
                    else:
                        print("Warning: Invalid ofByteBooks value while importing: " + str(val))
                        ofbytebooks = False
                except:
                    ofbytebooks = None

                handle_subkey(ParentKeyType, SubKeyType, value, master_key, method, ofbytebooks, None)
            except:
                pass

            j = j + 1
        
        i = i + 1

    return handle_subkey(None, None, None, master_key, None, None, buildIDtoEmulate)

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
    
    cert_key = data["activationServiceInfo"]["certificate"]
    if isinstance(cert_key, dict):
        if True in cert_key:
            content += "<adept:certificate ofByteBooks=\"true\">%s</adept:certificate>" % (cert_key[True])
        if False in cert_key:
            content += "<adept:certificate ofByteBooks=\"false\">%s</adept:certificate>" % (cert_key[False])
    else: 
        content += "<adept:certificate>%s</adept:certificate>" % (cert_key)

    authcert_key = data["activationServiceInfo"]["authenticationCertificate"]
    if isinstance(authcert_key, dict):
        if True in authcert_key:
            content += "<adept:authenticationCertificate ofByteBooks=\"true\">%s</adept:authenticationCertificate>" % (authcert_key[True])
        if False in authcert_key:
            content += "<adept:authenticationCertificate ofByteBooks=\"false\">%s</adept:authenticationCertificate>" % (authcert_key[False])
    else: 
        content += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (authcert_key)

    content += '</adept:activationServiceInfo>\n'

    content += '<adept:credentials xmlns:adept="http://ns.adobe.com/adept">'
    content += "<adept:user>%s</adept:user>" % (data["credentials"]["user"])
    global account_method
    if "username" in data["credentials"]:
        if account_method is None:
            account_method = "AdobeID"
    
        content += "<adept:username method=\"%s\">%s</adept:username>" % (account_method, xml_escape(data["credentials"]["username"]))


    pkcs12_key = data["credentials"]["pkcs12"]
    if isinstance(pkcs12_key, dict):
        if True in pkcs12_key:
            content += "<adept:pkcs12 ofByteBooks=\"true\">%s</adept:pkcs12>" % (pkcs12_key[True])
        if False in pkcs12_key:
            content += "<adept:pkcs12 ofByteBooks=\"false\">%s</adept:pkcs12>" % (pkcs12_key[False])
    else: 
        content += "<adept:pkcs12>%s</adept:pkcs12>" % (pkcs12_key)

    licenseCertificate_key = data["credentials"]["licenseCertificate"]
    if isinstance(licenseCertificate_key, dict):
        if True in licenseCertificate_key:
            content += "<adept:licenseCertificate ofByteBooks=\"true\">%s</adept:licenseCertificate>" % (licenseCertificate_key[True])
        if False in licenseCertificate_key:
            content += "<adept:licenseCertificate ofByteBooks=\"false\">%s</adept:licenseCertificate>" % (licenseCertificate_key[False])
    else: 
        content += "<adept:licenseCertificate>%s</adept:licenseCertificate>" % (licenseCertificate_key)
    
    content += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>" % (data["credentials"]["privateLicenseKey"])

    authCertificate_key = data["credentials"]["authenticationCertificate"]
    if isinstance(authCertificate_key, dict):
        if True in authCertificate_key:
            content += "<adept:authenticationCertificate ofByteBooks=\"true\">%s</adept:authenticationCertificate>" % (authCertificate_key[True])
        if False in authCertificate_key:
            content += "<adept:authenticationCertificate ofByteBooks=\"false\">%s</adept:authenticationCertificate>" % (authCertificate_key[False])
    else: 
        content += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (authCertificate_key)

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

def handle_subkey(parent, subkey, value, encryption_key, method, ofByteBooks, buildID):

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
        if not parent in persistent_data:
            persistent_data[parent] = dict()

        if ofByteBooks is None:
            persistent_data[parent][subkey] = value
        else:
            if subkey not in persistent_data[parent]:
                persistent_data[parent][subkey] = dict()

            persistent_data[parent][subkey][ofByteBooks] = value
    

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
    content += "<adept:fingerprint>%s</adept:fingerprint>\n" % (base64.b64encode(deviceFingerprint).decode("latin-1"))
    content += "</adept:deviceInfo>"

    # Write device.xml
    f = open(get_device_path(), "w")
    f.write(content)
    f.close()

    return True, "Success"