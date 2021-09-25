#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Helper library with code needed for Adobe stuff.
'''

from Crypto import Random
from uuid import getnode
import os, hashlib, base64
import urllib.request
from Crypto.Cipher import AES
from datetime import datetime, timedelta

from lxml import etree
import rsa


from Crypto.PublicKey import RSA
from Crypto.Hash import SHA

from oscrypto import keys
from oscrypto.asymmetric import dump_certificate, dump_private_key, dump_public_key



VAR_AUTH_SERVER = "adeactivate.adobe.com"
VAR_ACS_SERVER = "http://adeactivate.adobe.com/adept"
VAR_HOBBES_VERSION = "10.0.4"

FILE_DEVICEKEY = "devicesalt"
FILE_DEVICEXML = "device.xml"
FILE_ACTIVATIONXML = "activation.xml"

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


def update_account_path(folder_path: str):
    global FILE_DEVICEKEY, FILE_DEVICEXML, FILE_ACTIVATIONXML

    FILE_DEVICEKEY = os.path.join(folder_path, "devicesalt")
    FILE_DEVICEXML = os.path.join(folder_path, "device.xml")
    FILE_ACTIVATIONXML = os.path.join(folder_path, "activation.xml")


def createDeviceKeyFile():
    # Original implementation: Device::createDeviceKeyFile()

    DEVICE_KEY_SIZE = 16
    global devkey_bytes
    devkey_bytes = Random.get_random_bytes(DEVICE_KEY_SIZE)

    f = open(FILE_DEVICEKEY, "wb")
    f.write(devkey_bytes)
    f.close()

def get_mac_address(): 
    mac1 = getnode()
    mac2 = getnode()
    if (mac1 != mac2) or ((mac1 >> 40) % 2):
        return bytes([1, 2, 3, 4, 5, 0])
    
    return mac1.to_bytes(6, byteorder='big')



def makeSerial(random: bool):
    # Original implementation: std::string Device::makeSerial(bool random)

    sha_out = None

    if not random: 
        try:
            # Linux
            uid = os.getuid()
            import pwd
            username = pwd.getpwuid(uid).pw_name
        except: 
            # Windows
            uid = 1000
            username = os.getlogin()

        mac_address = get_mac_address()

        dataToHash = "%d:%s:%02x:%02x:%02x:%02x:%02x:%02x\x00" % (uid, username, 
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5])

        sha_out = hashlib.sha1(dataToHash.encode('latin-1')).hexdigest().lower()
    else: 
        sha_out = Random.get_random_bytes(20).hex().lower()

    return sha_out

def makeFingerprint(serial: str):
    # Original implementation: std::string Device::makeFingerprint(const std::string& serial)
    # base64(sha1(serial + privateKey))

    f = open(FILE_DEVICEKEY, "rb")
    devkey_bytes = f.read()
    f.close()

    str_to_hash = serial + devkey_bytes.decode('latin-1')
    hashed_str = hashlib.sha1(str_to_hash.encode('latin-1')).digest()
    b64str = base64.b64encode(hashed_str)

    return b64str


############################################## HTTP stuff:

def sendHTTPRequest_getSimple(URL: str):

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
    }
    req = urllib.request.Request(url=URL, headers=headers)
    handler = urllib.request.urlopen(req)

    content = handler.read()

    loc = None
    try: 
        loc = req.headers.get("Location")
    except:
        pass

    if loc is not None: 
        return sendHTTPRequest_getSimple(loc)

    return content

def sendPOSTHTTPRequest(URL: str, document: bytes, type: str):

    headers = {
        "Accept": "*/*",
        "User-Agent": "book2png",
        "Content-Type": type
    }
    req = urllib.request.Request(url=URL, headers=headers, data=document)
    handler = urllib.request.urlopen(req)

    content = handler.read()

    loc = None
    try: 
        loc = req.headers.get("Location")
    except:
        pass

    if loc is not None: 
        return sendPOSTHTTPRequest(loc, document, type)

    return content


def sendHTTPRequest(URL: str):
    return sendHTTPRequest_getSimple(URL)


def sendRequestDocu(document: str, URL: str):
    return sendPOSTHTTPRequest(URL, document.encode("utf-8"), "application/vnd.adobe.adept+xml")


######### Encryption and signing ###################


def encrypt_with_device_key(data):

    global devkey_bytes
    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    remain = 16
    if (len(data) % 16):
        remain = 16 - (len(data) % 16)

    data += bytes([remain])*remain

    iv = Random.get_random_bytes(16)
    cip = AES.new(devkey_bytes, AES.MODE_CBC, iv)
    encrypted = cip.encrypt(data)

    res = iv + encrypted
    return res

def decrypt_with_device_key(data): 
    global devkey_bytes
    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    cip = AES.new(devkey_bytes, AES.MODE_CBC, data[:16])
    decrypted = cip.decrypt(data[16:])

    # Remove padding
    decrypted = decrypted[:-decrypted[-1]]

    return decrypted


def addNonce(): 

    dt = datetime.utcnow()
    usec = dt.microsecond
    sec = (dt - datetime(1970,1,1)).total_seconds()

    nonce320 = int(0x6f046000)
    nonce321 = int(0x388a)
    bigtime = int(sec * 1000)

    nonce320 += int((bigtime & 0xFFFFFFFF) + usec/1000)
    nonce321 += int(((bigtime >> 32) & 0xFFFFFFFF))

    final = bytearray(nonce320.to_bytes(4, 'little'))
    final.extend(nonce321.to_bytes(4, 'little'))
    tmp = 0
    final.extend(tmp.to_bytes(4, 'little'))

    ret = ""

    ret += "<adept:nonce>%s</adept:nonce>" % (base64.b64encode(final).decode("utf-8"))

    m10m = dt + timedelta(minutes=10)
    m10m_str = m10m.strftime("%Y-%m-%dT%H:%M:%SZ")

    ret += "<adept:expiration>%s</adept:expiration>" % (m10m_str)

    return ret


def get_cert_from_pkcs12(_pkcs12, _key):

    _, cert, _ = keys.parse_pkcs12(_pkcs12, _key)
    cert = dump_certificate(cert, encoding="der")

    return cert


def sign_node(node):

    sha_hash = hash_node(node)
    sha_hash = sha_hash.digest()

    # print("Hash is " + sha_hash.hex())

    global devkey_bytes
    global pkcs12

    if devkey_bytes is None: 
        f = open(FILE_DEVICEKEY, "rb")
        devkey_bytes = f.read()
        f.close()

    try: 
        activationxml = etree.parse(FILE_ACTIVATIONXML)
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        pkcs12 = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("pkcs12"))).text
    except: 
        return None

    my_pkcs12 = base64.b64decode(pkcs12)
    my_priv_key, _, _ = keys.parse_pkcs12(my_pkcs12, base64.b64encode(devkey_bytes))
    my_priv_key = dump_private_key(my_priv_key, None, "der")

    key = rsa.PrivateKey.load_pkcs1(RSA.importKey(my_priv_key).exportKey())
    keylen = rsa.pkcs1.common.byte_size(key.n)
    padded = rsa.pkcs1._pad_for_signing(sha_hash, keylen)
    payload = rsa.pkcs1.transform.bytes2int(padded)
    encrypted = key.blinded_encrypt(payload)
    block = rsa.pkcs1.transform.int2bytes(encrypted, keylen)
    signature = base64.b64encode(block).decode()

    # print("sig is %s\n" % block.hex())

    return signature


 

def hash_node(node):

    hash_ctx = SHA.new()
    hash_node_ctx(node, hash_ctx)
    return hash_ctx



ASN_NONE = 0
ASN_NS_TAG = 1
ASN_CHILD = 2
ASN_END_TAG = 3
ASN_TEXT = 4
ASN_ATTRIBUTE = 5

debug = False

def hash_node_ctx(node, hash_ctx):

    qtag = etree.QName(node.tag)

    if (qtag.localname == "hmac"):
        return

    hash_do_append_tag(hash_ctx, ASN_NS_TAG)
    hash_do_append_string(hash_ctx, qtag.namespace)
    hash_do_append_string(hash_ctx, qtag.localname)


    attrKeys = node.keys()
    attrKeys.sort()
    for attribute in attrKeys: 
        hash_do_append_tag(hash_ctx, ASN_ATTRIBUTE)
        hash_do_append_string(hash_ctx, "")
        hash_do_append_string(hash_ctx, attribute)
        hash_do_append_string(hash_ctx, node.get(attribute))

    
    if (not len(list(node))):
        hash_do_append_tag(hash_ctx, ASN_CHILD)
        if (node.text is not None):
            hash_do_append_tag(hash_ctx, ASN_TEXT)
            hash_do_append_string(hash_ctx, node.text.strip()) 
        hash_do_append_tag(hash_ctx, ASN_END_TAG)
    else: 
        hash_do_append_tag(hash_ctx, ASN_CHILD)
        for child in node: 
            hash_node_ctx(child, hash_ctx)
        hash_do_append_tag(hash_ctx, ASN_END_TAG)


def hash_do_append_string(hash_ctx, string: str):

    str_bytes = bytes(string, encoding="utf-8")

    length = len(str_bytes)
    len_upper = int(length / 256)
    len_lower = int(length & 0xFF)

    hash_do_append_raw_bytes(hash_ctx, [len_upper, len_lower])
    hash_do_append_raw_bytes(hash_ctx, str_bytes)

def hash_do_append_tag(hash_ctx, tag: int):

    if (tag > 5):
        return
    
    hash_do_append_raw_bytes(hash_ctx, [tag])

def hash_do_append_raw_bytes(hash_ctx, data: bytes):
    hash_ctx.update(bytearray(data))
