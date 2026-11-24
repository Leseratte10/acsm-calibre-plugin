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
import sys, os, hashlib, base64
import ssl
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
from .customcrypto.customcrypto.asymmetric import dump_certificate, dump_private_key


VAR_ACS_SERVER_HTTPS = "https://activate.dtsbytebooks.com/adept"

# Network timeout in seconds. It applies to connecting and to every single read while
# waiting for or receiving a reply, so a slow but working download is not cut off.
VAR_HTTP_TIMEOUT = 30

# Errors that urllib does not wrap in a URLError, like a timeout or a dropped connection
# while waiting for or reading the reply. These all count as "server not reachable".
# (URLError is a subclass of these, so catch it first if it needs separate handling.)
HTTP_CONNECTION_ERRORS = (IOError, OSError, ulibhttp.HTTPException)

FILE_DEVICEKEY = "devicesalt"
FILE_DEVICEXML = "device.xml"
FILE_ACTIVATIONXML = "activation.xml"


# Lists of different ADE "versions" we know about
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


devkey_bytes = None



def get_devkey_path():
    global FILE_DEVICEKEY
    return FILE_DEVICEKEY
def get_device_path():
    global FILE_DEVICEXML
    return FILE_DEVICEXML
def get_activation_xml_path():
    global FILE_ACTIVATIONXML
    return FILE_ACTIVATIONXML


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

    f = open(FILE_DEVICEKEY, "wb")
    f.write(devkey_bytes)
    f.close()

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
            username = pwd.getpwuid(uid).pw_name.encode("utf-8").decode("latin-1")
        except: 
            # Windows
            uid = 1000
            try: 
                username = os.getlogin().encode("utf-8").decode("latin-1")
            except: 
                import getpass
                username = getpass.getuser().encode("utf-8").decode("latin-1")

        mac_address = get_mac_address()

        dataToHash = "%d:%s:%02x:%02x:%02x:%02x:%02x:%02x\x00" % (uid, username, 
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5])
            
        sha_out = hashlib.sha1(dataToHash.encode('latin-1')).hexdigest().lower()
    else: 
        # SHA1 of a bunch of random bytes
        sha_out = hashlib.sha1(Random.get_random_bytes(256)).hexdigest().lower()

    return sha_out

def makeFingerprint(serial):
    # type: (str) -> str

    # Original implementation: std::string Device::makeFingerprint(const std::string& serial)
    # base64(sha1(serial + privateKey))
    # Fingerprint must be 20 bytes or less.

    global devkey_bytes
    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    str_to_hash = serial + devkey_bytes.decode('latin-1')
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

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }

    ctx = create_ssl_context(validate_tls)

    try: 
        req = ulib.Request(url=URL, headers=headers)
        handler = ulib.urlopen(req, context=ctx, timeout=VAR_HTTP_TIMEOUT)
        try: 
            cl = handler.headers.get("Content-Length")
            cl = int(cl) if cl is not None else None
        except: 
            cl = None
        
        with open(outputfile, "wb") as f:
            received = 0
            chunksize = 16 * 1024
            while True:
                chunk = handler.read(chunksize)
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

            if cl is not None and received != cl: 
                print("Download aborted after %d out of %d bytes." % (received, cl))
                return 900

    except uliberror.HTTPError as err: 
        # This happens with HTTP 500 and related errors.
        return err.code

    except HTTP_CONNECTION_ERRORS as err:
        # Server not reachable, timeout, or the connection broke during the download.
        print("Download failed: %s" % (err))
        return 900

    finally: 
        handler.close()

    return 200

def sendHTTPRequest_getSimple(URL, validate_tls = True):
    # type: (str, bool) -> str

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
    }

    ctx = create_ssl_context(validate_tls)

    # Callers handle the exceptions, including the ones for a timeout.
    req = ulib.Request(url=URL, headers=headers)
    handler = ulib.urlopen(req, context=ctx, timeout=VAR_HTTP_TIMEOUT)

    content = handler.read()

    return content

def sendPOSTHTTPRequest(URL, document, contenttype, returnRC = False, validate_tls = True):
    # type: (str, bytes, str, bool, bool) -> str

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        # MacOS uses different User-Agent. Good thing we're emulating a Windows client.
        "Content-Type": contenttype
    }

    ctx = create_ssl_context(validate_tls)

    # Make sure URL has a protocol
    # Some vendors (see issue #22) apparently don't include "http://" in some of their URLs.
    # Python returns an error when it encounters such a URL, so just add that prefix if it's not present. 

    if not "://" in URL:
        print("Provider is using malformed URL %s, fixing." % (URL))
        URL = "http://" + URL

    req = ulib.Request(url=URL, headers=headers, data=document)
    try: 
        handler = ulib.urlopen(req, context=ctx, timeout=VAR_HTTP_TIMEOUT)

        ret_code = handler.getcode()
        if (ret_code == 204 and returnRC):
            return 204, ""
        if (ret_code != 200):
            print("Post request returned something other than 200 - returned %d" % (ret_code))

        content = handler.read()

    except uliberror.HTTPError as err: 
        # This happens with HTTP 500 and related errors.
        print("Post request caused HTTPError %d" % (err.code))
        if returnRC:
            return err.code, "Post request caused HTTPException"
        else:
            return None

    except uliberror.URLError as err: 
        # This happens if the hostname cannot be resolved, or (with validate_tls)
        # if the server's certificate chain can't be verified.
        print("Post request failed with URLError: %s" % (err.reason))
        if returnRC:
            return 900, "Post request failed with URLError"
        else: 
            return None

    except ssl.CertificateError as err:
        # Hostname mismatch with validate_tls. Python 2 and Python < 3.7 raise this
        # directly instead of wrapping it in a URLError like Python 3.7+ does.
        print("Post request failed, certificate does not match host: %s" % (err))
        if returnRC:
            return 900, "Post request failed with CertificateError"
        else:
            return None

    except HTTP_CONNECTION_ERRORS as err:
        # Timeout, or the connection broke while waiting for or reading the reply.
        print("Post request failed with %s: %s" % (type(err).__name__, err))
        if returnRC:
            return 900, "Post request failed with " + type(err).__name__
        else:
            return None

    if returnRC:
        return ret_code, content

    return content


def sendHTTPRequest(URL, validate_tls = True):
    # type: (str, bool) -> str
    return sendHTTPRequest_getSimple(URL, validate_tls)


def sendRequestDocu(document, URL, validate_tls = True):
    # type: (str, str, bool) -> str
    return sendPOSTHTTPRequest(URL, document.encode("utf-8"), "application/vnd.adobe.adept+xml", False, validate_tls)

def sendRequestDocuRC(document, URL, validate_tls = True):
    # type: (str, str, bool) -> str
    return sendPOSTHTTPRequest(URL, document.encode("utf-8"), "application/vnd.adobe.adept+xml", True, validate_tls)



######### Encryption and signing ###################


def encrypt_with_device_key(data):

    data = bytearray(data)

    global devkey_bytes
    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    remain = 16
    if (len(data) % 16):
        remain = 16 - (len(data) % 16)

    for _ in range(remain):
        data.append(remain)

    data = bytes(data)


    iv = Random.get_random_bytes(16)
    cip = AES.new(devkey_bytes, AES.MODE_CBC, iv)
    encrypted = cip.encrypt(data)

    res = iv + encrypted
    return res

def decrypt_with_device_key(data): 

    if isinstance(data, str):
        # Python2 
        data = bytes(data)

    global devkey_bytes
    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    cip = AES.new(devkey_bytes, AES.MODE_CBC, data[:16])
    decrypted = bytearray(cip.decrypt(data[16:]))

    # Remove padding
    decrypted = decrypted[:-decrypted[-1]]

    return decrypted


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
        final.extend(int_to_bytes(tmp, 4, True))


    ret = ""

    ret += "<adept:nonce>%s</adept:nonce>" % (base64.b64encode(final).decode("utf-8"))

    m10m = dt + datetime.timedelta(minutes=10)
    m10m_str = m10m.strftime("%Y-%m-%dT%H:%M:%SZ")

    ret += "<adept:expiration>%s</adept:expiration>" % (m10m_str)

    return ret


def get_cert_from_pkcs12(_pkcs12, _key):

    _, cert, _ = keys.parse_pkcs12(_pkcs12, _key)
    return dump_certificate(cert, encoding="der")




def sign_node(node, prefer_bytebooks):

    sha_hash = hash_node(node)
    sha_hash = sha_hash.digest()

    # print("Hash is " + sha_hash.hex())

    global devkey_bytes

    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    # Get private key


    activationxml = etree.parse(FILE_ACTIVATIONXML)
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # If prefer_bytebooks is set, this function will first try to use the ByteBooks cert. 
    # If it isn't, it tries the Adobe cert. 
    # If the requested one isn't found, it uses the other one.

    try: 
        pkcs12bb = activationxml.find("./%s/%s[@ofByteBooks='true']" % (adNS("credentials"), adNS("pkcs12"))).text
    except: 
        pkcs12bb = None

    try: 
        pkcs12adobe = next(
                        c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("pkcs12")))
                        if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
                        )
    except: 
        pkcs12adobe = None


    if pkcs12adobe is None and pkcs12bb is None: 
        return None

    if prefer_bytebooks:
        if pkcs12bb is not None: 
            pkcs12 = pkcs12bb
        else: 
            pkcs12 = pkcs12adobe
    else: 
        if pkcs12adobe is not None: 
            pkcs12 = pkcs12adobe
        else: 
            pkcs12 = pkcs12bb


    my_pkcs12 = base64.b64decode(pkcs12)
    my_priv_key, _, _ = keys.parse_pkcs12(my_pkcs12, base64.b64encode(devkey_bytes))
    my_priv_key = dump_private_key(my_priv_key, None, "der")

    # textbook RSA with that private key

    block = CustomRSA.encrypt_for_adobe_signature(my_priv_key, sha_hash)
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

    q_attribute = etree.QName(attribute)
    namespace = "" if q_attribute.namespace is None else q_attribute.namespace

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

    if qtag.namespace is None: 
        hash_do_append_string(hash_ctx, "")
    else:
        hash_do_append_string(hash_ctx, qtag.namespace)
    hash_do_append_string(hash_ctx, qtag.localname)


    # Attributes need to be sorted, see attribute_sort_key() for the exact order.
    attrKeys = sorted(node.keys(), key=attribute_sort_key)

    for attribute in attrKeys: 
        # Hash all the attributes
        hash_do_append_tag(hash_ctx, ASN_ATTRIBUTE)

        # Check for element namespace and hash that, if present:
        q_attribute = etree.QName(attribute)

        # Hash element namespace (usually "")
        # If namespace is none, use "". Else, use namespace.
        hash_do_append_string(hash_ctx, "" if q_attribute.namespace is None else q_attribute.namespace)

        # Hash (local) name and value
        hash_do_append_string(hash_ctx, q_attribute.localname)
        hash_do_append_string(hash_ctx, node.get(attribute))

    hash_do_append_tag(hash_ctx, ASN_CHILD)

    if (node.text is not None):
        # If there's raw text, hash that.

        # This code block used to just be the following:
        #   hash_do_append_tag(hash_ctx, ASN_TEXT)
        #   hash_do_append_string(hash_ctx, node.text.strip())
        # though that only works with text nodes < 0x7fff.
        # While I doubt we'll ever encounter text nodes larger than 32k in
        # this application, I want to implement the spec correctly.
        # So there's a loop going over the text, hashing 32k chunks.

        text = node.text.strip()

        if isinstance(text, bytes):
            text_bytes = text
        else:
            text_bytes = text.encode("utf-8")

        text_bytes_len = len(text_bytes)

        if text_bytes_len > 0:
            done = 0
            while True: 
                hash_do_append_tag(hash_ctx, ASN_TEXT)
                hashed_len = hash_do_append_string(hash_ctx, text_bytes[done:]) 
                if hashed_len is None or hashed_len == 0:
                    raise Exception("Error during hashing")

                done += hashed_len
                if done >= text_bytes_len:
                    break

    for child in node: 
        # If there's child nodes, hash these as well.
        hash_node_ctx(child, hash_ctx)



    hash_do_append_tag(hash_ctx, ASN_END_TAG)



def hash_do_append_string(hash_ctx, data):
    # type: (SHA.SHA1Hash, str|bytes) -> None|int

    if (isinstance(data, bytes)):
        str_bytes = data
    else:
        str_bytes = data.encode("utf-8")

        if len(str_bytes) > 0x7fff:
            # Trying to hash string longer than 0x7FFF, can't safely split.
            # This should never occur as long strings get handed into this function as bytes.
            return None
    

    length = len(str_bytes)

    if length >= 0x7fff:
        length = 0x7fff

    len_upper = int(length / 256)
    len_lower = int(length & 0xFF)

    hash_do_append_raw_bytes(hash_ctx, [len_upper, len_lower])
    hash_do_append_raw_bytes(hash_ctx, str_bytes[:length])

    return length

def hash_do_append_tag(hash_ctx, tag):
    # type: (SHA.SHA1Hash, int) -> None

    if (tag > 5):
        raise Exception("Tried to hash a tag outside of the valid range")
    
    hash_do_append_raw_bytes(hash_ctx, [tag])

def hash_do_append_raw_bytes(hash_ctx, data):
    # type: (SHA.SHA1Hash, bytes) -> None
    hash_ctx.update(bytearray(data))
