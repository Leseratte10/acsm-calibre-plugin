'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''


from lxml import etree
import base64, traceback
import os, re, struct
from xml.sax.saxutils import escape as xml_escape


try: 
    from Cryptodome.Cipher import AES as _AES
except ImportError:
    # Some distros still ship this as Crypto
    from Crypto.Cipher import AES as _AES


class AES(object):
    def __init__(self, key, iv):
        self._aes = _AES.new(key, _AES.MODE_CBC, iv)
    def decrypt(self, data):
        return self._aes.decrypt(data)


from .libadobe import makeSerial, safe_xml_parser, write_account_files, remove_padding
from .libadobe import VAR_VER_DEFAULT_BUILD_ID, VAR_VER_BUILD_IDS
from .libadobeAccount import build_device_xml


# The C escapes in Wine's registry files, see decode_wine_registry_string()
WINE_REGISTRY_ESCAPES = {"a": 7, "b": 8, "e": 27, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11}

def decode_wine_registry_string(value):
    # type: (str) -> str
    # Wine's user.reg is plain ASCII. Strings are stored with \x and up to four hex digits for
    # every UTF-16 code unit above 127, with \a \b \e \f \n \r \t \v or up to three octal digits
    # for control characters, and with a backslash in front of a backslash or a quote. This
    # decodes them the way Wine does when it loads the file (parse_strW in server/unicode.c).
    units = []      # UTF-16 code units
    i = 0
    while i < len(value):
        c = value[i]
        i += 1
        if c != "\\":
            code = ord(c)
            if code > 0xFFFF:
                code -= 0x10000
                units += [0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)]
            else:
                units.append(code)
            continue

        if i == len(value):
            # Wine drops a backslash at the very end
            break
        c = value[i]
        i += 1
        if c in WINE_REGISTRY_ESCAPES:
            units.append(WINE_REGISTRY_ESCAPES[c])
        elif c == "x":
            digits = re.match("[0-9a-fA-F]{1,4}", value[i:i + 4])
            if digits:
                units.append(int(digits.group(0), 16))
                i += len(digits.group(0))
            else:
                units.append(ord("x"))
        elif c in "01234567":
            digits = re.match("[0-7]{0,2}", value[i:i + 2]).group(0)
            units.append(int(c + digits, 8))
            i += len(digits)
        else:
            # Any other character after a backslash, like in \\ or \", stands for itself
            units.append(ord(c))

    # A character outside the BMP is two \x escapes, a UTF-16 surrogate pair
    return struct.pack("<%dH" % len(units), *units).decode("utf-16-le", "replace")


class WineActivationTree(object):
    # Collects the values of one activation tree in Wine's user.reg, see read_wine_activations()

    def __init__(self, key_prefix):
        self.key_prefix = key_prefix
        self.values = None          # stays None if the registry has no key in this tree
        self.in_tree = False
        self.parent = self.name = self.value = self.ofbytebooks = self.method = None

    def read_line(self, line):
        if line.startswith("["):
            # Start of a new registry key. Only collect values from keys inside this tree.
            self.in_tree = line.startswith(self.key_prefix)
            if self.in_tree and self.values is None:
                self.values = []
            return

        if not self.in_tree:
            return

        if (line.lower().startswith("@=")):
            self.name = decode_wine_registry_string(line.split('=', 1)[1].strip()[1:-1])

        elif (line.lower().startswith('"value"=')):
            self.value = decode_wine_registry_string(line.split('=', 1)[1].strip()[1:-1])

        elif (line.lower().startswith('"ofbytebooks"=')):
            # This attribute is a string, not an int.
            val = decode_wine_registry_string(line.split('=', 1)[1].strip()[1:-1])
            if str(val).lower() == "true" or val == True:
                self.ofbytebooks = True
            elif str(val).lower() == "false" or val == False:
                self.ofbytebooks = False
            else:
                print("Warning: Invalid ofByteBooks value while importing.")
                self.ofbytebooks = False

        elif (line.lower().startswith('"method"=')):
            self.method = decode_wine_registry_string(line.split('=', 1)[1].strip()[1:-1])

        elif (len(line) == 0):
            # Empty line - finalize this element. One without a value is a parent, like "credentials".
            if self.value is None:
                self.parent = self.name
                self.in_tree = False
            else:
                self.values.append((self.parent, self.name, self.value, self.method, self.ofbytebooks))
            self.name = self.value = self.ofbytebooks = self.method = None


def read_wine_activations(wine_prefix_path):
    # type: (str) -> dict
    # Reads the Adobe and the ByteBooks activation from the registry of a Wine prefix, in a
    # single pass over user.reg. Returns {False: Adobe, True: ByteBooks}, each None if the
    # registry has no such activation, or else a list of its values as (parent, name, value,
    # method, ofByteBooks) tuples for import_registry_activation().

    trees = {
        False: WineActivationTree("[Software\\\\Adobe\\\\Adept\\\\Activation\\\\"),
        True: WineActivationTree("[Software\\\\ByteBooks\\\\Adept\\\\Activation\\\\"),
    }

    registry_file = open(os.path.join(wine_prefix_path, "user.reg"), "r")
    try:
        for line in registry_file:
            line = line.strip()
            for tree in trees.values():
                tree.read_line(line)
    finally:
        registry_file.close()

    return dict((is_bytebooks, tree.values) for is_bytebooks, tree in trees.items())


def importADEactivationLinuxWine(wine_prefix_path, buildIDtoEmulate=VAR_VER_DEFAULT_BUILD_ID, activations=None):
    # Similar to importADEactivationWindows - extracts the activation data from a Wine prefix.
    # activations is what read_wine_activations() returned for this prefix, if the caller has
    # already read the registry. Otherwise it's read here.
    try:
        from calibre.constants import islinux
        if not islinux:
            print("This function is for Linux only!")
            return False, "Linux only!"
    except:
        pass

    try:
        if activations is None:
            activations = read_wine_activations(wine_prefix_path)
    except:
        traceback.print_exc()
        return False, "There has been an error while reading through the Registry."

    # Use the ByteBooks activation if it's complete, otherwise the Adobe one (same rule
    # as importADEactivationWindows). Only that tree gets imported, so the device key
    # has to come from the same Digital Editions install.
    root_is_bytebooks, error = choose_activation(activations)
    if root_is_bytebooks is None:
        return False, error

    # Get encryption key
    from .getEncryptionKeyLinux import GetMasterKey

    master_key = GetMasterKey(wine_prefix_path, root_is_bytebooks)

    if master_key is None:
        de_name = "BDE" if root_is_bytebooks else "ADE"
        err = "Could not access " + de_name + " encryption key. If you have just installed " + de_name + " in Wine, "
        err += "please reboot your machine then try again. Also, make sure neither " + de_name + " nor any other "
        err += "software is running in WINE while you're trying to import the authorization. "
        err += "If it still doesn't work but " + de_name + " in that particular WINEPREFIX is working fine, "
        err += "please open a bug report."

        return False, err

    try:
        return import_registry_activation(activations[root_is_bytebooks], master_key, buildIDtoEmulate)

    except:
        # There was an error hunting through the registry. 
        traceback.print_exc()
        return False, "There has been an error while reading through the Registry."

def read_windows_activation(winreg, key_path):
    # type: (object, str) -> list
    # Reads the activation in HKEY_CURRENT_USER\<key_path>, where ADE keeps every value in a key of
    # its own: the default value of Activation\0001 is a parent like "credentials", and the key
    # Activation\0001\0002 has the name of its third value as default value, and the value itself
    # in "value". Returns None if there is no such key, or else a list of (parent, name, value,
    # method, ofByteBooks) tuples for import_registry_activation(). Keys without a name or a value
    # are left out, choose_activation() then finds out if anything that's needed is missing.

    try:
        activation_root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
    except:
        return None

    values = []
    i = 0
    while True:
        try:
            activation_parent = winreg.OpenKey(activation_root, "%04d" % (i))
        except:
            break
        i = i + 1

        try:
            ParentKeyType = winreg.QueryValueEx(activation_parent, None)[0]
        except:
            continue

        j = 0
        while True:
            try:
                activation_child = winreg.OpenKey(activation_parent, "%04d" % (j))
            except:
                break
            j = j + 1

            try:
                SubKeyType = winreg.QueryValueEx(activation_child, None)[0]
                value = winreg.QueryValueEx(activation_child, 'value')[0]
            except:
                continue

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

            values.append((ParentKeyType, SubKeyType, value, method, ofbytebooks))

    return values

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

    try:
        activations = {
            False: read_windows_activation(winreg, r'Software\Adobe\Adept\Activation'),
            True: read_windows_activation(winreg, r'Software\ByteBooks\Adept\Activation'),
        }
    except:
        traceback.print_exc()
        return False, "There has been an error while reading through the Registry."

    # Use the ByteBooks activation if it's complete, otherwise the Adobe one
    root_is_bytebooks, error = choose_activation(activations)
    if root_is_bytebooks is None:
        return False, error

    # Get encryption key:
    from .getEncryptionKeyWindows import GetMasterKey

    master_key = GetMasterKey(root_is_bytebooks)

    if master_key is None: 
        if root_is_bytebooks:
            return False, "Could not access BDE encryption key"
        else:
            return False, "Could not access ADE encryption key"

    try:
        return import_registry_activation(activations[root_is_bytebooks], master_key, buildIDtoEmulate)
    except:
        # There was an error in the values from the registry
        traceback.print_exc()
        return False, "There has been an error while reading through the Registry."

def vendor_elements(name, value):
    # type: (str, str|dict) -> str
    # The <adept:name> elements for an activation value: one per vendor with the ofByteBooks
    # flag if the value is a dict ({True: ByteBooks, False: Adobe}), else one without it.
    if isinstance(value, dict):
        ret = ""
        for flag in (True, False):
            if flag in value:
                ret += "<adept:%s ofByteBooks=\"%s\">%s</adept:%s>" % (name, "true" if flag else "false", xml_escape(value[flag]), name)
        return ret
    return "<adept:%s>%s</adept:%s>" % (name, xml_escape(value), name)

def finalize_write_config_Windows(data, key, buildID, account_method=None):
    # Okay, finally got all the data that's needed - recreate all the files.

    # Create activation.xml
    content = '<?xml version="1.0"?>\n'
    content += "<activationInfo xmlns=\"http://ns.adobe.com/adept\">\n"
    content += '<adept:activationServiceInfo xmlns:adept="http://ns.adobe.com/adept">\n'

    content += "<adept:authURL>%s</adept:authURL>" % (xml_escape(data["activationServiceInfo"]["authURL"]))
    content += "<adept:userInfoURL>%s</adept:userInfoURL>" % (xml_escape(data["activationServiceInfo"]["userInfoURL"]))
    content += "<adept:activationURL>%s</adept:activationURL>" % (xml_escape(data["activationServiceInfo"]["activationURL"]))
    
    content += vendor_elements("certificate", data["activationServiceInfo"]["certificate"])

    if "authenticationCertificate" in data["activationServiceInfo"]:
        authcert_key = data["activationServiceInfo"]["authenticationCertificate"]
    elif "authenticationCertificate" in data["credentials"]:
        # Not sure what that's needed for, I think this cert is always identical ...
        authcert_key = data["credentials"]["authenticationCertificate"]
    else: 
        authcert_key = None

    if authcert_key is not None:
        content += vendor_elements("authenticationCertificate", authcert_key)

    content += '</adept:activationServiceInfo>\n'

    content += '<adept:credentials xmlns:adept="http://ns.adobe.com/adept">'
    content += "<adept:user>%s</adept:user>" % (data["credentials"]["user"])
    if "username" in data["credentials"]:
        content += "<adept:username method=\"%s\">%s</adept:username>" % (account_method or "AdobeID", xml_escape(data["credentials"]["username"]))


    content += vendor_elements("pkcs12", data["credentials"]["pkcs12"])
    content += vendor_elements("licenseCertificate", data["credentials"]["licenseCertificate"])
    content += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>" % (data["credentials"]["privateLicenseKey"])
    content += vendor_elements("authenticationCertificate", data["credentials"]["authenticationCertificate"])

    content += '</adept:credentials>\n'

    content += '<activationToken xmlns="http://ns.adobe.com/adept">'

    for x in ["device", "fingerprint", "deviceType", "activationURL", "user", "signature"]:
        content += "<%s>%s</%s>" % (x, data["activationToken"][x], x)

    content += '</activationToken>\n'
    content += '</activationInfo>\n'

    # Re-create device.xml from scratch:
    version_idx = VAR_VER_BUILD_IDS.index(buildID)
    serial = makeSerial(False)
    try:
        dev_content = build_device_xml(data["activationToken"]["deviceType"], serial, data["activationToken"]["fingerprint"], version_idx)
    except ValueError as e:
        return False, "The activation contains invalid data: %s" % (e)

    # Content prepared, now replace all three files together.
    try:
        write_account_files(device_key=key, device_xml=dev_content, activation_xml=content.encode("utf-8"))
    except (IOError, OSError) as e:
        return False, "Can't write the account files: %s" % (e)

    return True, "Done"

def collect_activation_values(values):
    # type: (list) -> tuple
    # Sorts the values of an activation, as (parent, name, value, method, ofByteBooks) tuples,
    # into a dict of dicts: data[parent][name] is the value or, for a key that the registry
    # has in a ByteBooks and an Adobe variant, a dict of both values with True and False as
    # keys. Returns that dict and the account's login method.

    data = dict()
    account_method = None

    for parent, name, value, method, ofByteBooks in values:
        if method:
            account_method = method

        if not parent in data:
            data[parent] = dict()

        stored_variants = name in data[parent] and isinstance(data[parent][name], dict)

        if ofByteBooks is None and not stored_variants:
            # Plain value, and no ByteBooks / Adobe variants of this key so far.
            data[parent][name] = value
        else:
            # This key exists in a ByteBooks and an Adobe variant. An entry without the
            # ofByteBooks flag counts as Adobe (same as everywhere else in the plugin),
            # so store it as False. A plain value stored earlier for the same key is
            # converted the same way, so the two styles can be mixed in any order.
            if ofByteBooks is None:
                ofByteBooks = False

            if name not in data[parent]:
                data[parent][name] = dict()
            elif not stored_variants:
                data[parent][name] = { False: data[parent][name] }

            data[parent][name][ofByteBooks] = value

    return data, account_method

# The values that finalize_write_config_Windows() needs from an activation
REQUIRED_ACTIVATION_VALUES = [
    ("activationServiceInfo", "authURL"), ("activationServiceInfo", "userInfoURL"),
    ("activationServiceInfo", "activationURL"), ("activationServiceInfo", "certificate"),
    ("credentials", "user"), ("credentials", "pkcs12"), ("credentials", "licenseCertificate"),
    ("credentials", "privateLicenseKey"), ("credentials", "authenticationCertificate"),
    ("activationToken", "device"), ("activationToken", "fingerprint"), ("activationToken", "deviceType"),
    ("activationToken", "activationURL"), ("activationToken", "user"), ("activationToken", "signature"),
]

def choose_activation(activations):
    # type: (dict) -> tuple
    # Picks the activation to import from {False: Adobe, True: ByteBooks}, each None or a list
    # of its values (as read_wine_activations() and read_windows_activation() return them):
    # the ByteBooks one if it has all the values the import needs, otherwise the Adobe one.
    # Returns (True or False, None), or (None, an error message) if neither one is complete.

    missing = {}
    for is_bytebooks in (True, False):
        if activations[is_bytebooks] is not None:
            data = collect_activation_values(activations[is_bytebooks])[0]
            missing[is_bytebooks] = ["%s/%s" % (parent, name) for parent, name in REQUIRED_ACTIVATION_VALUES
                                     if name not in data.get(parent, {})]
            if not missing[is_bytebooks]:
                return is_bytebooks, None

    if not missing:
        return None, "Could not locate an ADE or BDE activation"

    # Report what the preferred activation lacks
    is_bytebooks = True in missing
    return None, "The %s activation is incomplete, it lacks %s" % (
        "BDE" if is_bytebooks else "ADE", ", ".join(missing[is_bytebooks]))

def import_registry_activation(values, encryption_key, buildID):
    # type: (list, bytes, int) -> tuple
    # Imports an activation that the Windows or the Wine import read from the registry, as a
    # list of (parent, name, value, method, ofByteBooks) tuples: decrypts the private license
    # key with the encryption key, then writes the account files.

    data, account_method = collect_activation_values(values)

    # The first 16 bytes of the fingerprint are used as IV for the privateLicenseKey
    # Older versions of this decryption code, like in the DeDRM plugin, didn't
    # do that correctly. For DeDRM that doesn't matter as a wrong IV only causes
    # the first 16 bytes to be corrupted, and these aren't used for eBook decryption anyways.
    # For this plugin I want the exact correct data, so lets use the fingerprint as IV.
    # See jhowell's post: https://www.mobileread.com/forums/showpost.php?p=4173908

    iv = data["activationToken"]["fingerprint"]
    iv = base64.b64decode(iv)[:16]
    aes = AES(encryption_key, iv)

    value = base64.b64decode(data["credentials"]["privateLicenseKey"])
    try:
        decrypted_key = remove_padding(aes.decrypt(value))
    except ValueError:
        return False, "Could not decrypt the private license key, the encryption key doesn't seem to match this activation."

    data["credentials"]["privateLicenseKey"] = base64.b64encode(decrypted_key).decode("latin-1")

    return finalize_write_config_Windows(data, encryption_key, buildID, account_method)

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


def findMacActivationDat(home):
    # Returns the path of the BDE or ADE activation.dat in the given home folder, or None.
    # Use the ByteBooks activation if there is one, otherwise the Adobe one (same rule as
    # the Windows and Wine imports). Both keep their keys in the same keychain entries.

    for vendor in ["ByteBooks", "Adobe"]:
        de_folder = os.path.join(home, "Library", "Application Support", vendor, "Digital Editions")
        for dirpath, dirnames, filenames in os.walk(de_folder):
            if "activation.dat" in filenames:
                return os.path.join(dirpath, "activation.dat")

    return None


def importADEactivationMac(buildIDtoEmulate=VAR_VER_DEFAULT_BUILD_ID):
    # Tries to import the system activation from ByteBooks or Adobe Digital Editions on a Mac into the plugin
    # This can be used to "clone" the BDE/ADE activation so you don't need to waste an additional activation.

    import sys

    try: 
        from calibre.constants import isosx
    except:
        isosx = sys.platform.startswith('darwin')

    if not isosx:
        print("This function is for MacOS only!")
        return False, "MacOS only!"

    ActDatPath = findMacActivationDat(os.path.expanduser("~"))

    if ActDatPath is None:
        print("Activation file does not exist ...")
        return False, "Activation file not found"

    print("Importing activation from %s" % (ActDatPath))


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
    
    # Read and check activation.dat before anything is written, so a broken or
    # de-authorized file doesn't leave a half imported account behind.
    try:
        with open(path_to_activation, "rb") as f:
            activation_data = f.read()
        activationxml = etree.fromstring(activation_data, parser=safe_xml_parser()).getroottree()
    except (IOError, OSError, etree.XMLSyntaxError) as e:
        return False, "Can't read activation.dat: %s" % (e)

    # The plugin parses its own account files with lxml's default parser, so just like
    # the ZIP import, don't import a file with a DOCTYPE.
    if activationxml.docinfo.doctype:
        return False, "activation.dat has an invalid format"

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    devtype_node = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("deviceType")))
    if devtype_node is None or not devtype_node.text:
        return False, "activation.dat contains no authorization. Is Digital Editions authorized?"
    devtype = devtype_node.text


    # Re-create device.xml from scratch:
    version_idx = VAR_VER_BUILD_IDS.index(buildIDtoEmulate)
    serial = makeSerial(False)
    try:
        dev_content = build_device_xml(devtype, serial, base64.b64encode(deviceFingerprint).decode("latin-1"), version_idx)
    except ValueError as e:
        return False, "activation.dat contains invalid data: %s" % (e)

    # Content prepared, now replace all three files together. activation.xml is
    # activation.dat, byte for byte.
    try:
        write_account_files(device_key=deviceKey, device_xml=dev_content, activation_xml=activation_data)
    except (IOError, OSError) as e:
        return False, "Can't write the account files: %s" % (e)

    return True, "Success"