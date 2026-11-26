#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

'''
Helper library with code needed for Adobe stuff.
'''

from uuid import getnode
import sys, os, hashlib, base64, platform, tempfile, stat, traceback
import ssl, threading
try: 
    import urllib.request as ulib
    import urllib.error as uliberror
    import http.client as ulibhttp
except: 
    import urllib2 as ulib
    import urllib2 as uliberror
    import httplib as ulibhttp

import datetime

from lxml import etree

try:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA

except ImportError:
    # Some distros still ship Crypto
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA


from .customRSA import CustomRSA

from .customcrypto.customcrypto import keys


VAR_ACS_SERVER_HTTPS = "https://activate.dtsbytebooks.com/adept"

# Network timeout in seconds. It applies to connecting and to every single read while
# waiting for or receiving a reply, so a slow but working download is not cut off.
VAR_HTTP_TIMEOUT = 30

# Time limit in seconds for a whole ADEPT request in send_adept(). VAR_HTTP_TIMEOUT alone
# doesn't end a request if the server sends a byte every now and then.
VAR_HTTP_REQUEST_TIME_LIMIT = 60

# Errors that urllib does not wrap in a URLError, like a timeout or a dropped connection
# while waiting for or reading the reply. These all count as "server not reachable".
# (URLError is a subclass of these, so catch it first if it needs separate handling.)
HTTP_CONNECTION_ERRORS = (IOError, OSError, ulibhttp.HTTPException)

# sendHTTPRequest_DL2FILE returns this instead of an HTTP status code if it can't write the
# download to the output file (no permission, disk full, ...). Network errors are 900.
DOWNLOAD_FILE_ERROR = 901

FILE_DEVICEKEY = "devicesalt"
FILE_DEVICEXML = "device.xml"
FILE_ACTIVATIONXML = "activation.xml"


# Lists of different ADE "versions" we know about
# This is kinda redundant at the moment since there's only one version we emulate, 
# but all the code to handle multiple versions is still there, so when ByteBooks
# releases a new version, this should be easy to adapt. 

VAR_VER_SUPP_CONFIG_NAMES = [ "BDE 5.0.76" ]
VAR_VER_SUPP_VERSIONS = [ "com.dtsbytebooks.digitaleditions.exe v5.0.76" ]
VAR_VER_HOBBES_VERSIONS = [ "12.5.4.HOBBES_VERSION_BUILD_NUMBER_X" ] 
# Yes, that last version is correct, looks like ByteBooks messed up their placeholder.
VAR_VER_OS_IDENTIFIERS = [ "Windows 8" ]



# This is a list of ALL versions we know (and can potentially use if present in a config file).
VAR_VER_BUILD_IDS = [ 76 ]

# This is a list of versions that can be used for new authorizations:
VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE = [ 76 ]

# Default build ID to use - ADE 5.0
VAR_VER_DEFAULT_BUILD_ID = 76



def are_ade_version_lists_valid():
    # These five lists MUST all have the same amount of elements. 
    # Otherwise that will cause all kinds of issues. 

    fail = False
    if len(VAR_VER_SUPP_CONFIG_NAMES) != len(VAR_VER_SUPP_VERSIONS):
        fail = True
    if len(VAR_VER_SUPP_CONFIG_NAMES) != len(VAR_VER_HOBBES_VERSIONS):
        fail = True
    if len(VAR_VER_SUPP_CONFIG_NAMES) != len(VAR_VER_OS_IDENTIFIERS):
        fail = True
    if len(VAR_VER_SUPP_CONFIG_NAMES) != len(VAR_VER_BUILD_IDS):
        fail = True
    
    if fail:
        print("Internal error in ACSM Input: Mismatched version list lenghts.")
        print("This should never happen, please open a bug report.")
        return False
    
    return True


devkey_bytes = None     # cached by get_device_key()



def get_devkey_path():
    global FILE_DEVICEKEY
    return FILE_DEVICEKEY
def get_device_path():
    global FILE_DEVICEXML
    return FILE_DEVICEXML
def get_activation_xml_path():
    global FILE_ACTIVATIONXML
    return FILE_ACTIVATIONXML


def safe_xml_parser():
    # type: () -> etree.XMLParser
    # Returns a new parser for XML the plugin didn't write itself: server replies,
    # ACSM files, files from an eReader or an import, and requests that contain parts
    # of those. It doesn't resolve entities and never loads anything over the network,
    # so a DOCTYPE can't pull a local file or a URL into the document (XXE). Before
    # lxml 5.0, the default parser resolved external entities, including local files.
    return etree.XMLParser(resolve_entities=False, no_network=True)


def replace_file(src, dst):
    # type: (str, str) -> None
    # Renames src to dst. An existing dst is replaced in one step, so there's always either
    # the old or the new file under that name.
    if hasattr(os, "replace"):
        # Python 3.3 and newer
        os.replace(src, dst)
    elif sys.platform == "win32":
        # Python 2 on Windows, where os.rename fails if dst exists. This is what os.replace does.
        import ctypes
        MOVEFILE_REPLACE_EXISTING = 0x1
        MOVEFILE_WRITE_THROUGH = 0x8
        text = type(u"")
        if not isinstance(src, text):
            src = src.decode("mbcs")
        if not isinstance(dst, text):
            dst = dst.decode("mbcs")
        if not ctypes.windll.kernel32.MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH):
            raise ctypes.WinError()
    else:
        # Python 2 on Linux and macOS, where os.rename replaces dst in one step
        os.rename(src, dst)


def write_files_atomically(files):
    # type: (list) -> None
    # Writes the (path, data) pairs without ever leaving a truncated or empty file behind.
    # Each file is first written completely to a temporary file in the same folder, and
    # only once all of them are written, they replace the old files. If anything fails
    # before that (a full disk, an unplugged eReader, a killed process), the old files
    # stay as they are.

    renames = []        # (temporary file, file)
    try:
        for path, data in files:
            # Write the target of a symlink, and keep the symlink
            path = os.path.realpath(path)
            folder, name = os.path.split(path)

            fd, tmp_path = tempfile.mkstemp(prefix=name + ".", suffix=".tmp", dir=folder)
            renames.append((tmp_path, path))
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

            # mkstemp creates the file for the owner only. Keep the permissions of an existing file.
            try:
                os.chmod(tmp_path, stat.S_IMODE(os.stat(path).st_mode))
            except OSError:
                pass

        for tmp_path, path in renames:
            replace_file(tmp_path, path)
    except:
        # Remove the temporary files that weren't renamed
        for tmp_path, path in renames:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


def write_file_atomically(path, data):
    # type: (str, bytes) -> None
    # See write_files_atomically()
    write_files_atomically([(path, data)])


def update_account_path(folder_path):
    # type: (str) -> None

    global FILE_DEVICEKEY, FILE_DEVICEXML, FILE_ACTIVATIONXML, devkey_bytes

    FILE_DEVICEKEY = os.path.join(folder_path, "devicesalt")
    FILE_DEVICEXML = os.path.join(folder_path, "device.xml")
    FILE_ACTIVATIONXML = os.path.join(folder_path, "activation.xml")

    # force reloading the device key when it is next used.
    devkey_bytes = None


def createDeviceKeyFile():

    DEVICE_KEY_SIZE = 16
    global devkey_bytes
    devkey_bytes = Random.get_random_bytes(DEVICE_KEY_SIZE)

    write_file_atomically(FILE_DEVICEKEY, devkey_bytes)


def get_device_key():
    # type: () -> bytes
    # Returns the device key from devicesalt. The file is only read once: functions
    # that change devicesalt or the account folder update or reset the cached key.

    global devkey_bytes
    if devkey_bytes is None:
        with open(FILE_DEVICEKEY, "rb") as f:
            devkey_bytes = f.read()
    return devkey_bytes


def write_account_files(device_key, device_xml, activation_xml):
    # type: (bytes, bytes, bytes) -> None
    # Replaces devicesalt, device.xml and activation.xml together, see write_files_atomically().
    # Use this instead of writing devicesalt directly, so the cached device key is reset.

    global devkey_bytes
    try:
        write_files_atomically([
            (FILE_DEVICEKEY, device_key),
            (FILE_DEVICEXML, device_xml),
            (FILE_ACTIVATIONXML, activation_xml),
        ])
    finally:
        # Even if writing fails, some of the files may have been replaced
        devkey_bytes = None

def int_to_bytes(value, length, big_endian = True):
    # Helper function for Python2 only (big endian)
    # Python3 uses int.to_bytes()
    result = []

    for i in range(0, length):
        result.append(value >> (i * 8) & 0xff)

    if big_endian:
        result.reverse()

    return result

def get_mac_address(): 
    mac1 = getnode()
    mac2 = getnode()
    if (mac1 != mac2) or ((mac1 >> 40) % 2):
        if sys.version_info[0] >= 3:
            return bytes([1, 2, 3, 4, 5, 0])
        else: 
            return bytearray([1, 2, 3, 4, 5, 0])
    
    if sys.version_info[0] >= 3:
        return mac1.to_bytes(6, byteorder='big')

    return int_to_bytes(mac1, 6)
    




def os_string_to_text(value):
    # type: (str|bytes) -> str
    # Python 2 returns names from the operating system, like the user name or the
    # computer name, as byte strings in the system's encoding: the ANSI code page on
    # Windows, usually UTF-8 everywhere else. Python 3 already returns text.
    if isinstance(value, bytes):
        try:
            return value.decode("mbcs" if sys.platform == "win32" else "utf-8")
        except UnicodeDecodeError:
            # Not in the expected encoding. Latin-1 can decode any bytes.
            return value.decode("latin-1")
    return value


def get_device_name():
    # type: () -> str
    # The computer name for device.xml, as text. On Python 2, lxml rejects the byte
    # string platform.uname() returns if the name isn't ASCII.
    return os_string_to_text(platform.uname()[1])


def makeSerial(random):
    # type: (bool) -> str

    # Original implementation: std::string Device::makeSerial(bool random)

    # It doesn't look like this implementation results in the same fingerprint Adobe is using in ADE.
    # Given that Adobe only ever sees the SHA1 hash of this value, that probably doesn't matter.

    sha_out = None

    if not random: 
        try:
            # Linux
            uid = os.getuid()
            import pwd
            username = os_string_to_text(pwd.getpwuid(uid).pw_name)
        except: 
            # Windows
            uid = 1000
            try: 
                username = os_string_to_text(os.getlogin())
            except: 
                import getpass
                username = os_string_to_text(getpass.getuser())

        mac_address = get_mac_address()

        dataToHash = "%d:%s:%02x:%02x:%02x:%02x:%02x:%02x\x00" % (uid, username, 
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5])
            
        # The user name is hashed as UTF-8, everything else in the string is ASCII.
        sha_out = hashlib.sha1(dataToHash.encode("utf-8")).hexdigest().lower()
    else: 
        # SHA1 of a bunch of random bytes
        sha_out = hashlib.sha1(Random.get_random_bytes(256)).hexdigest().lower()

    return sha_out

def makeFingerprint(serial):
    # type: (str) -> str

    # Original implementation: std::string Device::makeFingerprint(const std::string& serial)
    # base64(sha1(serial + privateKey))
    # Fingerprint must be 20 bytes or less.

    str_to_hash = serial + get_device_key().decode('latin-1')
    hashed_str = hashlib.sha1(str_to_hash.encode('latin-1')).digest()
    b64str = base64.b64encode(hashed_str)

    return b64str


############################################## HTTP stuff:

calibre_ca_locations = None

def get_calibre_ca_locations():
    # type: () -> tuple
    # Returns (cafile, capath) for the Mozilla CA bundle that ships with Calibre.
    # Newer Calibre versions ship it as a hashed directory ("mozilla-ca-certs"),
    # older ones as a single PEM file ("mozilla-ca-certs.pem").
    # Returns (None, None) outside of Calibre (standalone scripts, tests) or if
    # this Calibre install doesn't contain the bundle (some distro packages strip it).

    global calibre_ca_locations
    if calibre_ca_locations is not None:
        return calibre_ca_locations

    cafile = None
    capath = None
    try:
        from calibre.utils.resources import get_path    # type: ignore

        # allow_user_override=False, same as Calibre itself uses for its CA files,
        # so a file in the user's Calibre config folder can't replace the trusted CAs.
        path = get_path("mozilla-ca-certs", allow_user_override=False)
        if os.path.isdir(path):
            capath = path
        else:
            path = get_path("mozilla-ca-certs.pem", allow_user_override=False)
            if os.path.isfile(path):
                cafile = path
    except Exception:
        pass

    calibre_ca_locations = (cafile, capath)
    return calibre_ca_locations


def create_ssl_context(validate_tls):
    # type: (bool) -> ssl.SSLContext

    ctx = ssl.create_default_context()

    if validate_tls:
        # Python 3.13 added VERIFY_X509_STRICT to the default context. It rejects certificate
        # chains that browsers, ADE and older Python versions accept, for instance a certificate
        # without an Authority Key Identifier or a CA whose basicConstraints aren't marked
        # critical. Turn it off, so that every Python version accepts the same servers.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

        # Also trust the CA bundle that ships with Calibre. Windows only downloads root
        # certificates into its store when Windows itself needs one, so verification can
        # fail for a perfectly valid server certificate whose root Windows hasn't fetched yet.
        cafile, capath = get_calibre_ca_locations()
        if cafile is not None or capath is not None:
            try:
                ctx.load_verify_locations(cafile=cafile, capath=capath)
            except Exception:
                # A broken bundle must not stop us from using the system certificates.
                print("Couldn't load Calibre's CA certificates, using the system ones only.")
    else:
        # It appears as if lots of book distributors have either invalid or expired certs ...
        # No idea how Adobe handles that (pinning?), but we can just ignore SSL errors and continue anyways.
        # Order matters here, too: check_hostname must be disabled before CERT_NONE.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


def sendHTTPRequest_DL2FILE(URL, outputfile, validate_tls = True):
    # type: (str, str, bool) -> int
    # Returns 200, the HTTP status code of an error reply, 900 for network errors (no
    # connection, timeout, incomplete download), or DOWNLOAD_FILE_ERROR.

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }

    ctx = create_ssl_context(validate_tls)
    handler = None

    try: 
        req = ulib.Request(url=URL, headers=headers)
        handler = ulib.urlopen(req, context=ctx, timeout=VAR_HTTP_TIMEOUT)
        try: 
            cl = handler.headers.get("Content-Length")
            cl = int(cl) if cl is not None else None
        except: 
            cl = None
        
        # Errors from the output file (no permission, disk full, ...) are local problems,
        # so they're reported separately instead of as network errors.
        try:
            with open(outputfile, "wb") as f:
                received = 0
                chunksize = 16 * 1024
                while True:
                    try:
                        chunk = handler.read(chunksize)
                    except HTTP_CONNECTION_ERRORS as err:
                        # The connection broke during the download.
                        print("Download failed: %s" % (err))
                        return 900
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
        except EnvironmentError as err:
            print("Can't save the download to %s: %s" % (outputfile, err))
            return DOWNLOAD_FILE_ERROR

        if cl is not None and received != cl:
            print("Download aborted after %d out of %d bytes." % (received, cl))
            return 900

    except uliberror.HTTPError as err: 
        # This happens with HTTP 500 and related errors.
        return err.code

    except HTTP_CONNECTION_ERRORS as err:
        # Server not reachable, or no reply (timeout, dropped connection).
        print("Download failed: %s" % (err))
        return 900

    finally: 
        if handler is not None:
            handler.close()

    return 200

class RequestError(Exception):
    # Raised by send_adept() if a request gets no usable reply. The message says why.
    pass


def send_adept(url, document, validate_tls, allow_no_content = False):
    # type: (str, str, bool, bool) -> etree._Element
    # Sends an ADEPT request: a POST with the XML document, or a GET if document is None.
    # Returns the root element of the reply, which can be an ADEPT <error>. With
    # allow_no_content, an empty reply with HTTP status 204 returns None instead.
    # Raises RequestError for everything else: a URL that can't be used, no connection,
    # a timeout, a certificate that isn't valid (with validate_tls), an HTTP error, a
    # reply that isn't XML, or no reply within VAR_HTTP_REQUEST_TIME_LIMIT seconds.

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }

    data = None
    if document is not None:
        headers["Content-Type"] = "application/vnd.adobe.adept+xml"
        data = document.encode("utf-8")

    # Make sure URL has a protocol
    # Some vendors (see issue #22) apparently don't include "http://" in some of their URLs.
    # Python returns an error when it encounters such a URL, so just add that prefix if it's not present.

    if not "://" in url:
        print("Provider is using malformed URL %s, fixing." % (url))
        url = "http://" + url

    # The request runs in a thread of its own, so it can be given up after the time limit.
    # That thread is then left to finish (or hang) on its own, its result is ignored.
    result = {}
    def request():
        try:
            req = ulib.Request(url=url, headers=headers, data=data)
            handler = ulib.urlopen(req, context=create_ssl_context(validate_tls), timeout=VAR_HTTP_TIMEOUT)
            try:
                result["reply"] = (handler.getcode(), handler.read())
            finally:
                handler.close()
        except BaseException as err:
            result["error"] = err

    thread = threading.Thread(target=request, name="ACSM Input request")
    thread.daemon = True    # don't keep Calibre from exiting
    thread.start()
    thread.join(VAR_HTTP_REQUEST_TIME_LIMIT)
    if thread.is_alive():
        raise RequestError("Request to %s failed: no complete reply within %d seconds" % (url, VAR_HTTP_REQUEST_TIME_LIMIT))

    try:
        if "error" in result:
            raise result["error"]
        status, reply = result["reply"]

    except uliberror.HTTPError as err:
        raise RequestError("%s replied with HTTP error %d" % (url, err.code))

    except HTTP_CONNECTION_ERRORS + (ValueError,) as err:
        # No connection, a timeout or a dropped connection, a certificate error (a ValueError
        # in Python 2), or a URL that can't be sent, like one with non-ASCII characters.
        raise RequestError("Request to %s failed: %s" % (url, err))

    if status == 204 and allow_no_content:
        return None
    if status != 200:
        print("Request to %s returned HTTP status %s" % (url, status))

    try:
        return etree.fromstring(reply, parser=safe_xml_parser())
    except etree.XMLSyntaxError as err:
        # That includes an empty reply
        raise RequestError("Invalid reply from %s: %s" % (url, err))


def xml_to_text(element):
    # type: (etree._Element) -> str
    # The element as XML text, for messages and the log
    return etree.tostring(element, encoding="unicode")



######### Encryption and signing ###################


def encrypt_with_device_key(data):

    data = bytearray(data)

    remain = 16
    if (len(data) % 16):
        remain = 16 - (len(data) % 16)

    for _ in range(remain):
        data.append(remain)

    data = bytes(data)


    iv = Random.get_random_bytes(16)
    cip = AES.new(get_device_key(), AES.MODE_CBC, iv)
    encrypted = cip.encrypt(data)

    res = iv + encrypted
    return res

def remove_padding(data):
    # type: (bytes) -> bytes
    # Removes the PKCS#7 padding after AES-CBC decryption, with the same checks as
    # customcrypto, so a wrong key raises ValueError instead of returning garbage.
    # Not Crypto.Util.Padding.unpad(), which PyCrypto 2.6 (in Calibre 3) doesn't have.

    data = bytearray(data)
    pad = data[-1] if data else 0
    if not 1 <= pad <= 16 or data[-pad:] != bytearray([pad]) * pad:
        raise ValueError("Decryption failed - invalid padding, the key may be incorrect")
    return bytes(data[:-pad])

def decrypt_with_device_key(data):

    if isinstance(data, str):
        # Python2 
        data = bytes(data)

    cip = AES.new(get_device_key(), AES.MODE_CBC, data[:16])
    return remove_padding(cip.decrypt(data[16:]))


def addNonce(): 

    # TODO: Update nonce calculation
    # Currently, the plugin always uses the current time, and the counter (tmp) is always 0. 
    # What Adobe does instead is save the current time on program start, then increase tmp
    # every time a Nonce is needed. 

    if sys.version_info < (3, 7, 0):
        # https://blog.miguelgrinberg.com/post/it-s-time-for-a-change-datetime-utcnow-is-now-deprecated 
        dt = datetime.datetime.utcnow()
        sec = (dt - datetime.datetime(1970,1,1)).total_seconds()
    else: 
        dt = datetime.datetime.now(datetime.timezone.utc)
        sec = (dt - datetime.datetime(1970,1,1, tzinfo=datetime.timezone.utc)).total_seconds()


    Ntime = int(sec * 1000)
    # Ntime is now milliseconds since 1970

    # Unixtime to gregorian timestamp
    Ntime += 62167219200000

    # Something is fishy with this tmp value. It usually is 0 in ADE, but not always. 
    # I haven't yet figured out what it means ...
    tmp = 0

    if sys.version_info[0] >= 3:
        final = bytearray(Ntime.to_bytes(8, 'little'))
        final.extend(tmp.to_bytes(4, 'little'))
    else:
        final = bytearray(int_to_bytes(Ntime, 8, False))
        final.extend(int_to_bytes(tmp, 4, False))


    ret = ""

    ret += "<adept:nonce>%s</adept:nonce>" % (base64.b64encode(final).decode("utf-8"))

    m10m = dt + datetime.timedelta(minutes=10)
    m10m_str = m10m.strftime("%Y-%m-%dT%H:%M:%SZ")

    ret += "<adept:expiration>%s</adept:expiration>" % (m10m_str)

    return ret


def get_cert_from_pkcs12(_pkcs12, _key):

    _, cert, _ = keys.parse_pkcs12(_pkcs12, _key)
    return cert.dump()


def find_vendor_values(parent, *tags):
    # type: (etree._Element, str) -> tuple
    # Activations and server replies contain some values once per vendor. This returns
    # (ByteBooks, Adobe) for the adept elements at parent/tags[0]/tags[1]/...: the text of the
    # first element with ofByteBooks="true", and of the first one with ofByteBooks="false" or
    # without the attribute, which activations from ADE and older plugin versions don't have.
    # Elements without text are skipped, and a vendor without a value is None.

    path = "./" + "/".join("{http://ns.adobe.com/adept}" + tag for tag in tags)

    bytebooks = None
    adobe = None
    for element in parent.findall(path):
        if not element.text:
            continue
        flag = element.get("ofByteBooks")
        if flag == "true":
            if bytebooks is None:
                bytebooks = element.text
        elif flag is None or flag == "false":
            if adobe is None:
                adobe = element.text

    return bytebooks, adobe


def prefer_vendor(bytebooks, adobe, prefer_bytebooks):
    # type: (str, str, bool) -> tuple
    # Picks one of the values that find_vendor_values() returned: the ByteBooks one if
    # prefer_bytebooks is set, otherwise the Adobe one, and the other one if that's None.
    # Returns (value, is_bytebooks), or (None, None) if both are None.

    if bytebooks is not None and (prefer_bytebooks or adobe is None):
        return bytebooks, True
    if adobe is not None:
        return adobe, False
    return None, None




def sign_node(node, prefer_bytebooks):
    # type: (etree._Element, bool) -> str
    # Returns the signature for the node in base64, or None if it can't be signed.
    # All callers check for None, so a missing or broken devicesalt, activation.xml
    # or pkcs12 has to return None here instead of raising an exception, and so does
    # a node that can't be hashed.

    try:
        sha_hash = hash_node(node).digest()
    except Exception:
        print("Signing failed, can't hash the node:")
        traceback.print_exc()
        return None

    # print("Hash is " + sha_hash.hex())

    # Get private key

    try:
        device_key = get_device_key()
        activationxml = etree.parse(FILE_ACTIVATIONXML)
    except Exception:
        print("Signing failed, can't read devicesalt or activation.xml:")
        traceback.print_exc()
        return None

    # If prefer_bytebooks is set, this function will first try to use the ByteBooks cert. 
    # If it isn't, it tries the Adobe cert. 
    # If the requested one isn't found, it uses the other one.

    pkcs12bb, pkcs12adobe = find_vendor_values(activationxml, "credentials", "pkcs12")
    pkcs12, is_bytebooks = prefer_vendor(pkcs12bb, pkcs12adobe, prefer_bytebooks)

    if pkcs12 is None:
        print("Signing failed, activation.xml doesn't contain a pkcs12")
        return None

    vendor = "ByteBooks" if is_bytebooks else "Adobe"


    try:
        my_pkcs12 = base64.b64decode(pkcs12)
        my_priv_key, _, _ = keys.parse_pkcs12(my_pkcs12, base64.b64encode(device_key))
        if my_priv_key is None:
            raise ValueError("The pkcs12 doesn't contain a private key")
        my_priv_key = my_priv_key.dump()

        # textbook RSA with that private key

        block = CustomRSA.encrypt_for_adobe_signature(my_priv_key, sha_hash)
    except Exception:
        # A wrong device key, a corrupt pkcs12, or one that customcrypto can't read
        print("Signing failed, can't use the %s pkcs12:" % (vendor))
        traceback.print_exc()
        return None

    signature = base64.b64encode(block).decode()

    # Debug
    # print("sig is %s\n" % block.hex())

    return signature


 

def hash_node(node):

    hash_ctx = SHA.new()
    hash_node_ctx(node, hash_ctx)
    return hash_ctx



ASN_NONE = 0
ASN_NS_TAG = 1      # aka "BEGIN_ELEMENT"
ASN_CHILD = 2       # aka "END_ATTRIBUTES"
ASN_END_TAG = 3     # aka "END_ELEMENT"
ASN_TEXT = 4        # aka "TEXT_NODE"
ASN_ATTRIBUTE = 5   # aka "ATTRIBUTE"

# The characters that are trimmed from both ends of a text node before it's hashed. The
# server runs on Java and trims like String.strip(), which removes what Character.isWhitespace()
# counts as whitespace: ASCII whitespace and the Unicode space, line and paragraph separators,
# but not the non-breaking spaces U+00A0, U+2007 and U+202F. (U+000B, U+000C and U+001C to
# U+001F are part of Java's definition, but can't appear in XML.)
JAVA_WHITESPACE = (u"\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f\x20"
                   u"\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
                   u"\u2006\u2008\u2009\u200a\u2028\u2029\u205f\u3000")

debug = False

def attribute_sort_key(attribute):
    # type: (str) -> tuple

    # "Attributes are sorted first by their namespaces and
    # then by their names; sorting is done bytewise on UTF-8
    # representations."

    # lxml returns attribute keys in Clark notation ("{namespace}name", or just "name"),
    # so sorting the raw keys isn't quite right: a namespace that is a prefix of another one
    # can sort after it ("{http://a/x}..." < "{http://a}..." because "/" < "}"), and attributes 
    # without a namespace whose name starts with a non-ASCII character would sort after all 
    # namespaced ones (because "{" < "\u00e9"). So split the key into namespace and local name, 
    # with "" for "no namespace" (which then always comes first), and compare their UTF-8 bytes. 
    # Comparing bytes instead of strings also keeps the order correct on Python 2 builds that 
    # store unicode strings as UTF-16, where characters outside the BMP would sort wrongly.
    #
    # In C this would be a simple memcmp.

    q_attribute = etree.QName(attribute)
    namespace = q_attribute.namespace or ""

    return (namespace.encode("utf-8"), q_attribute.localname.encode("utf-8"))


def hash_node_ctx(node, hash_ctx):

    qtag = etree.QName(node.tag)

    if (qtag.localname == "hmac" or qtag.localname == "signature"):
        if (qtag.namespace == "http://ns.adobe.com/adept"):
            # Adobe HMAC and signature are not hashed
            return
        else: 
            print("Warning: Found hmac or signature node in unexpected namespace " + str(qtag.namespace))

    hash_do_append_tag(hash_ctx, ASN_NS_TAG)
    hash_do_append_string(hash_ctx, qtag.namespace or "")
    hash_do_append_string(hash_ctx, qtag.localname)


    # Attributes need to be sorted, see attribute_sort_key() for the exact order.
    for attribute in sorted(node.keys(), key=attribute_sort_key): 
        q_attribute = etree.QName(attribute)

        hash_do_append_tag(hash_ctx, ASN_ATTRIBUTE)
        hash_do_append_string(hash_ctx, q_attribute.namespace or "")
        hash_do_append_string(hash_ctx, q_attribute.localname)
        hash_do_append_string(hash_ctx, node.get(attribute))


    hash_do_append_tag(hash_ctx, ASN_CHILD)

    # lxml has no separate text nodes: the text in front of the first child is
    # node.text, and the text after a child is that child's .tail.
    text = node.text

    for child in node: 
        if child.tag in (etree.Comment, etree.ProcessingInstruction):
            # lxml also returns comments and processing instructions as children, with
            # etree.Comment or etree.ProcessingInstruction as their .tag. They aren't
            # hashed, and the text in front of and after them is one text node, as if
            # they weren't in the XML at all.

            # This line of code merges the text before the comment (from node.text)
            # and the text after the comment (child.tail) together into one text node
            # before hashing.
            text = (text or "") + (child.tail or "")
            continue

        if child.tag is etree.Entity:
            # A reference to an entity that a DOCTYPE defines (&name;), which the safe
            # parser doesn't resolve and the server doesn't support.
            raise ValueError("Can't hash XML that contains the entity reference %s" % (child.text))

        # Hash the text that lives in *front* of the first child node.
        hash_text_node(hash_ctx, text)

        # Hash all the child nodes.
        hash_node_ctx(child, hash_ctx)

        # If there's text left after the child, either process it during the next loop 
        # iteration (if there is one), or hash it separately after this loop.
        text = child.tail

    hash_text_node(hash_ctx, text)
    hash_do_append_tag(hash_ctx, ASN_END_TAG)


def hash_text_node(hash_ctx, text):
    # type: (SHA.SHA1Hash, str|None) -> None
    # Hashes a text node, unless it's empty after trimming.

    if text is None:
        return

    # Caution, server-client mismatch:
    # The server (ACS) strips any character in JAVA_WHITESPACE, because it runs in Java and 
    # just calls String.strip().
    # The client (ADE) is written in C and only strips isspace() in the C locale, meaning, 
    # only the bytes \x20, \t, \n, \x0b, \x0c, \r.
    # This means that an official ADE client would be unable to sign a request in a way
    # the server would accept it, if this request contains any whitespace that is included
    # in JAVA_WHITESPACE but not in isspace(). 

    # A client that behaves 100% like ADE would need to use isspace(). 
    # A client that is supposed to work with as many ACSM files as possible would need to 
    # use JAVA_WHITESPACE, which is what this code implements.

    text = text.strip(JAVA_WHITESPACE)

    if isinstance(text, bytes):
        text_bytes = text
    else:
        text_bytes = text.encode("utf-8")

    text_bytes_len = len(text_bytes)

    if text_bytes_len > 0:
        offset = 0
        while True:
            # Caution, another server-client mismatch:
            # The server (ACS) splits a text node into multiple text nodes, each with their own ASN_TEXT
            # identifier, as soon as a text node is longer than 0x7FFF. 
            # The client (ADE) doesn't, it just sends the lower two bytes of the full string length, then
            # the full string. 
            # This means that an official ADE client would be unable to sign a request in a way the server
            # would accept it, if it contains a node whose text content is longer than 0x7FFF. 
            # If the text node we want to hash is longer than 0x7FFF, split it up into multiple text nodes. 
            #
            # Since we want to be as compatible with as many ACSM files as possible, we use the rule the 
            # server accepts, which splits longer strings into chunks. 
            hash_do_append_tag(hash_ctx, ASN_TEXT)

            len_to_hash = min(0x7FFF, text_bytes_len)
            hash_do_append_string(hash_ctx, text_bytes[offset:offset+len_to_hash])

            offset += len_to_hash
            if offset >= text_bytes_len:
                break



def hash_do_append_string(hash_ctx, data):
    # type: (SHA.SHA1Hash, str|bytes) -> None

    if (isinstance(data, bytes)):
        str_bytes = data
    else:
        str_bytes = data.encode("utf-8")

    length = len(str_bytes)

    # Only the two lower bytes of the length
    # If the string is longer than 0xFFFF, 
    # we still only use these two bytes here, but we do hash the full string.
    # Note: This rule only applies to attributes or values or similar, it does
    # NOT apply to text nodes. For those, see hash_text_node.
    len_upper = int((length // 256) & 0xFF)
    len_lower = int(length & 0xFF)

    hash_do_append_raw_bytes(hash_ctx, [len_upper, len_lower])
    hash_do_append_raw_bytes(hash_ctx, str_bytes)

    return

def hash_do_append_tag(hash_ctx, tag):
    # type: (SHA.SHA1Hash, int) -> None

    if (tag > 5):
        raise Exception("Tried to hash a tag outside of the valid range")
    
    hash_do_append_raw_bytes(hash_ctx, [tag])

def hash_do_append_raw_bytes(hash_ctx, data):
    # type: (SHA.SHA1Hash, bytes) -> None
    hash_ctx.update(bytearray(data))
