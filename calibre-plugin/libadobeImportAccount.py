'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''


from lxml import etree
import base64, traceback
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

    global persistent_data, account_method
    persistent_data = dict()
    account_method = None

    # Loop through the registry:
    try: 
        # Use the ByteBooks activation if there is one, otherwise the Adobe one
        # (same rule as importADEactivationWindows). Only that tree gets imported.
        root_is_bytebooks = False
        registry_file = open(os.path.join(wine_prefix_path, "user.reg"), "r")
        for line in registry_file:
            if line.strip().startswith("[Software\\\\ByteBooks\\\\Adept\\\\Activation\\\\"):
                root_is_bytebooks = True
                break
        registry_file.close()

        if root_is_bytebooks:
            activation_prefix = "[Software\\\\ByteBooks\\\\Adept\\\\Activation\\\\"
        else: 
            activation_prefix = "[Software\\\\Adobe\\\\Adept\\\\Activation\\\\"

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

            if line.startswith("["):
                # Start of a new registry key. Only collect values from keys inside the
                # activation tree picked above, and stop as soon as we leave it.
                waiting_for_element = line.startswith(activation_prefix)
                continue

            if waiting_for_element:
                if (line.lower().startswith("@=")): 
                    current_name = line.split('=', 1)[1].strip()[1:-1]
                    continue
                
                if (line.lower().startswith('"value"=')): 
                    current_value = line.split('=', 1)[1].strip()[1:-1]
                    continue

                if (line.lower().startswith('"ofbytebooks"=')): 
                    # This attribute is a string, not an int.
                    val = line.split('=', 1)[1].strip()[1:-1]
                    if str(val).lower() == "true" or val == True:
                        current_ofbytebooks = True
                    elif str(val).lower() == "false" or val == False:
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


                                
        registry_file.close()
        return handle_subkey(None, None, None, master_key, None, None, buildIDtoEmulate)

    except: 
        # There was an error hunting through the registry. 
        traceback.print_exc()
        return False, "There has been an error while reading through the Registry."

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

    # Dump data from registry:
    try:
        import winreg
    except ImportError:
        import _winreg as winreg

    root_is_bytebooks = None
    try: 
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\ByteBooks\Adept\Activation\0000')
        activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\ByteBooks\Adept\Activation')
        root_is_bytebooks = True
    except: 
        try: 
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Adobe\Adept\Activation\0000')
            activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Adobe\Adept\Activation')
            root_is_bytebooks = False
        except: 
            return False, "Could not locate ADE activation"

    # Get encryption key:
    from getEncryptionKeyWindows import GetMasterKey

    master_key = GetMasterKey(root_is_bytebooks)

    if master_key is None: 
        if root_is_bytebooks:
            return False, "Could not access BDE encryption key"
        else:
            return False, "Could not access ADE encryption key"


    global persistent_data, account_method
    persistent_data = dict()
    account_method = None

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
                    if str(val).lower() == "true" or val == True:
                        ofbytebooks = True
                    elif str(val).lower() == "false" or val == False:
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

    f = open(get_activation_xml_path(), "wb")
    f.write(content.encode("utf-8"))
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
    f = open(get_device_path(), "wb")
    f.write(content.encode("utf-8"))
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
        decrypted_key = bytearray(aes.decrypt(value))

        # Remove padding
        decrypted_key = bytes(decrypted_key[:-decrypted_key[-1]])

        persistent_data["credentials"]["privateLicenseKey"] = base64.b64encode(decrypted_key).decode("latin-1")


        return finalize_write_config_Windows(persistent_data, encryption_key, buildID)
    else: 
        # collecting a single sub key by storing it in the global list "persistent_data"
        global account_method
        if method:
            account_method = method

        # Not encrypted
        if not parent in persistent_data:
            persistent_data[parent] = dict()

        stored_variants = subkey in persistent_data[parent] and isinstance(persistent_data[parent][subkey], dict)

        if ofByteBooks is None and not stored_variants:
            # Plain value, and no ByteBooks / Adobe variants of this key so far.
            persistent_data[parent][subkey] = value
        else:
            # This key exists in a ByteBooks and an Adobe variant. An entry without the
            # ofByteBooks flag counts as Adobe (same as everywhere else in the plugin),
            # so store it as False. A plain value stored earlier for the same key is
            # converted the same way, so the two styles can be mixed in any order.
            if ofByteBooks is None:
                ofByteBooks = False

            if subkey not in persistent_data[parent]:
                persistent_data[parent][subkey] = dict()
            elif not stored_variants:
                persistent_data[parent][subkey] = { False: persistent_data[parent][subkey] }

            persistent_data[parent][subkey][ofByteBooks] = value
    

    return None

def getMacCredential(type):

    import os, re, binascii

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
            return binascii.unhexlify(hexform)
        elif isinstance(stringform, bytes):
            return stringform
        else:
            return stringform.encode('latin-1')
        
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

    # TODO: Add support for the ByteBooks path
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
    f = open(get_device_path(), "wb")
    f.write(content.encode("utf-8"))
    f.close()

    return True, "Success"