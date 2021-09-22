#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
This is an experimental Python version of libgourou. Right now it only supports part of the authorization
(and doesn't support fulfillment at all). All the encryption / decryption stuff works, the node hashing
also works, only thing I'm stuck at is the signature. Right now the Adobe server responds with "BadPadding".

Who knows, maybe there will someday be a full Python version of libgourou so it can be used in 
Calibre on all operating systems without additional dependencies.
'''


# pyright: reportUndefinedVariable=false

import os, pwd, hashlib, base64, locale, urllib.request, datetime
from datetime import datetime, timedelta
from OpenSSL import crypto
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from uuid import getnode
from lxml import etree


VAR_MAIL = "test@example.com"
VAR_PASS = "mypassword"
VAR_AUTH_SERVER = "adeactivate.adobe.com"
VAR_ACS_SERVER = "http://adeactivate.adobe.com/adept"
VAR_HOBBES_VERSION = "10.0.4"

FILE_DEVICEKEY = "devicesalt"
FILE_DEVICEXML = "device.xml"
FILE_ACTIVATIONXML = "activation.xml"

devkey_bytes = None
authkey_pub = None
authkey_priv = None
licensekey_pub = None
licensekey_priv = None

user_uuid = None
pkcs12 = None

def createDeviceKeyFile():
    # Original implementation: Device::createDeviceKeyFile()

    global devkey_bytes

    DEVICE_KEY_SIZE = 16
    devkey = Random.get_random_bytes(DEVICE_KEY_SIZE)
    devkey_bytes = devkey

    f = open(FILE_DEVICEKEY, "wb")
    f.write(devkey)
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
        uid = os.getuid()
        passwd = pwd.getpwuid(uid)
        mac_address = get_mac_address()

        dataToHash = "%d:%s:%02x:%02x:%02x:%02x:%02x:%02x\x00" % (uid, passwd.pw_name, 
            mac_address[0], mac_address[1], mac_address[2], 
            mac_address[3], mac_address[4], mac_address[5])

        sha_out = hashlib.sha1(dataToHash.encode('latin-1')).hexdigest().lower()
    else: 
        sha_out = Random.get_random_bytes(20).hex().lower()

    return sha_out

def makeFingerprint(serial: str):
    # Original implementation: std::string Device::makeFingerprint(const std::string& serial)
    # base64(sha1(serial + privateKey))

    if (devkey_bytes is None):
        print("devkey is None!")
        exit()

    str_to_hash = serial + devkey_bytes.decode('latin-1')
    hashed_str = hashlib.sha1(str_to_hash.encode('latin-1')).digest()
    b64str = base64.b64encode(hashed_str)

    return b64str


def createDeviceFile(hobbes: str, randomSerial: bool): 
    # Original implementation: Device::createDeviceFile(const std::string& hobbes, bool randomSerial)
    sysname = os.uname()

    serial = makeSerial(randomSerial)
    fingerprint = makeFingerprint(serial)

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "deviceInfo"))
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceClass")).text = "Desktop"
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceSerial")).text = serial
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceName")).text = sysname.nodename
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceType")).text = "standalone"

    atr_ver = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver.set("name", "hobbes")
    atr_ver.set("value", hobbes)

    atr_ver2 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver2.set("name", "clientOS")
    atr_ver2.set("value", sysname.sysname + " " + sysname.release)

    atr_ver3 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver3.set("name", "clientLocale")
    atr_ver3.set("value", locale.getdefaultlocale()[0])

    etree.SubElement(root, etree.QName(NSMAP["adept"], "fingerprint")).text = fingerprint

    f = open(FILE_DEVICEXML, "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()


def createDevice():
    createDeviceKeyFile()
    createDeviceFile(VAR_HOBBES_VERSION, False)

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

    try: 
        ct = req.headers.get("Content-Type")
    except: 
        ct = None

    if ct == "application/vnd.adobe.adept+xml":
        print("Got adobe XML")

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

    try: 
        ct = req.headers.get("Content-Type")
    except: 
        ct = None

    if ct == "application/vnd.adobe.adept+xml":
        print("Got adobe XML")

    return content


def sendHTTPRequest(URL: str):
    return sendHTTPRequest_getSimple(URL)

def sendRawRequest(URL: str): 
    return sendHTTPRequest(URL)


def sendRequestDocu(document: str, URL: str):
    return sendPOSTHTTPRequest(URL, document.encode("latin-1"), "application/vnd.adobe.adept+xml")


def createUser(): 

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }

    root = etree.Element("activationInfo")
    root.set("xmlns", NSMAP["adept"])

    etree.register_namespace("adept", NSMAP["adept"])

    activationServiceInfo = etree.SubElement(root, etree.QName(NSMAP["adept"], "activationServiceInfo"))

    
    activationURL = VAR_ACS_SERVER + "/ActivationServiceInfo"
    response = sendRawRequest(activationURL)

    print(response)

    adobe_response_xml = etree.fromstring(response)

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    authURL = adobe_response_xml.find("./%s" % (adNS("authURL"))).text
    userInfoURL = adobe_response_xml.find("./%s" % (adNS("userInfoURL"))).text
    certificate = adobe_response_xml.find("./%s" % (adNS("certificate"))).text

    if (authURL is None or userInfoURL is None or certificate is None):
        print("Error: Unexpected reply from Adobe.")
        exit()

    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authURL")).text = authURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "userInfoURL")).text = userInfoURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "certificate")).text = certificate


    authenticationURL = authURL + "/AuthenticationServiceInfo"
    response2 = sendRawRequest(authenticationURL)
    adobe_response_xml2 = etree.fromstring(response2)
    authCert = adobe_response_xml2.find("./%s" % (adNS("certificate"))).text
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authenticationCertificate")).text = authCert


    f = open(FILE_ACTIVATIONXML, "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()
    return

def buildSignInRequest(adobeID: str, adobePassword: str, authenticationCertificate: str):
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "signIn"))
    root.set("method", "AdobeID")

    global devkey_bytes
    deviceKey = devkey_bytes
    _authenticationCertificate = base64.b64decode(authenticationCertificate)

    # Build buffer <deviceKey> <len username> <username> <len password> <password>

    ar = bytearray(deviceKey)
    ar.extend(bytearray(len(adobeID).to_bytes(1, 'big')))
    ar.extend(bytearray(adobeID.encode("latin-1")))
    ar.extend(bytearray(len(adobePassword).to_bytes(1, 'big')))
    ar.extend(bytearray(adobePassword.encode("latin-1")))

    # Crypt code from https://stackoverflow.com/a/12921889/4991648
    cert = DerSequence()
    cert.decode(_authenticationCertificate)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    rsakey = RSA.importKey(subjectPublicKeyInfo)
    cipherAC = PKCS1_v1_5.new(rsakey)
    crypted_msg = cipherAC.encrypt(bytes(ar))

    print(crypted_msg)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "signInData")).text = base64.b64encode(crypted_msg)

    # Generate Auth key and License Key
    authkey = RSA.generate(1024, e=65537)
    licensekey = RSA.generate(1024, e=65537)

    global authkey_pub, authkey_priv, licensekey_pub, licensekey_priv

    authkey_pub = authkey.publickey().exportKey("DER")
    authkey_priv = authkey.exportKey("DER")
    authkey_priv_enc = encrypt_with_device_key(authkey_priv) 

    licensekey_pub = licensekey.publickey().exportKey("DER")
    licensekey_priv = licensekey.exportKey("DER")
    licensekey_priv_enc = encrypt_with_device_key(licensekey_priv) 


    etree.SubElement(root, etree.QName(NSMAP["adept"], "publicAuthKey")).text = base64.b64encode(authkey_pub)
    etree.SubElement(root, etree.QName(NSMAP["adept"], "encryptedPrivateAuthKey")).text = base64.b64encode(authkey_priv_enc)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "publicLicenseKey")).text = base64.b64encode(licensekey_pub)
    etree.SubElement(root, etree.QName(NSMAP["adept"], "encryptedPrivateLicenseKey")).text = base64.b64encode(licensekey_priv_enc)

    print(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")
    

def signIn(username: str, passwd: str):


    # Get authenticationCertificate
    activationxml = etree.parse(FILE_ACTIVATIONXML)
    print(activationxml)
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    authenticationCertificate = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authenticationCertificate"))).text

    signInRequest = buildSignInRequest(username, passwd, authenticationCertificate)

    signInURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text + "/SignInDirect"

    credentials = sendRequestDocu(signInRequest, signInURL)
    print (credentials)

    try: 
        credentialsXML = etree.fromstring(credentials)
        
        if (credentialsXML.tag == adNS("error")): 
            err = credentialsXML.get("data")
            if ("E_AUTH_FAILED" in err and "CUS05051" in err): 
                print("Invalid username or password!")
            else: 
                print("Unknown Adobe error:")
                print(credentials)
            
            exit()
        elif (credentialsXML.tag == adNS("credentials")):
            print("Login successful")
        else: 
            print("Invalid main tag " + credentialsXML.tag)
            exit()

    
    except: 
        print("Invalid response to login request")
        exit()

    # Got correct credentials

    private_key_data_encrypted = credentialsXML.find("./%s" % (adNS("encryptedPrivateLicenseKey"))).text
    private_key_data_encrypted = base64.b64decode(private_key_data_encrypted)
    private_key_data = decrypt_with_device_key(private_key_data_encrypted)


    # Okay, now we got the credential response correct. Now "just" apply all these to the main activation.xml

    f = open(FILE_ACTIVATIONXML, "w")

    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1").replace("</activationInfo>", ""))

    # Yeah, that's ugly, but I didn't get etree to work with the different Namespaces ...

    f.write("<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n")
    f.write("<adept:user>%s</adept:user>\n" % (credentialsXML.find("./%s" % (adNS("user"))).text))
    f.write("<adept:username method=\"%s\">%s</adept:username>\n" % (credentialsXML.find("./%s" % (adNS("username"))).get("method", "AdobeID"), credentialsXML.find("./%s" % (adNS("username"))).text))
    f.write("<adept:pkcs12>%s</adept:pkcs12>\n" % (credentialsXML.find("./%s" % (adNS("pkcs12"))).text))
    f.write("<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (credentialsXML.find("./%s" % (adNS("licenseCertificate"))).text))
    f.write("<adept:privateLicenseKey>%s</adept:privateLicenseKey>\n" % (base64.b64encode(private_key_data).decode("latin-1")))
    f.write("<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (authenticationCertificate))
    f.write("</adept:credentials>\n")
    f.write("</activationInfo>\n")

    f.close()

    global user_uuid
    user_uuid = credentialsXML.find("./%s" % (adNS("user"))).text

    global pkcs12
    pkcs12 = credentialsXML.find("./%s" % (adNS("pkcs12"))).text



def encrypt_with_device_key(data):

    global devkey_bytes
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

    cip = AES.new(devkey_bytes, AES.MODE_CBC, data[:16])
    decrypted = cip.decrypt(data[16:])

    # Remove padding
    decrypted = decrypted[:-decrypted[-1]]

    return decrypted




def addNonce(): 

    dt = datetime.now()
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

    ret += "<adept:nonce>%s</adept:nonce>" % (base64.b64encode(final).decode("latin-1"))

    m10m = datetime.now() + timedelta(minutes=10)
    m10m_str = m10m.strftime("%Y-%m-%dT%H:%M:%SZ")

    ret += "<adept:expiration>%s</adept:expiration>" % (m10m_str)

    return ret



def buildActivateReq(): 

    devicexml = etree.parse(FILE_DEVICEXML)
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)


    version = None
    clientOS = None
    clientLocale = None

    ver = devicexml.findall("./%s" % (adNS("version")))


    for f in ver:
        if f.get("name") == "hobbes":
            version = f.get("value")
        elif f.get("name") == "clientOS":
            clientOS = f.get("value")
        elif f.get("name") == "clientLocale":
            clientLocale = f.get("value")

    if (version is None or clientOS is None or clientLocale is None):
        print("err")
        return

        
    ret = ""

    ret += "<?xml version=\"1.0\"?>"
    ret += "<adept:activate xmlns:adept=\"http://ns.adobe.com/adept\" requestType=\"initial\">"
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (devicexml.find("./%s" % (adNS("fingerprint"))).text)
    ret += "<adept:deviceType>%s</adept:deviceType>" % (devicexml.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (devicexml.find("./%s" % (adNS("deviceClass"))).text)
    ret += "<adept:targetDevice>"


    ret += "<adept:softwareVersion>%s</adept:softwareVersion>" % (version)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (devicexml.find("./%s" % (adNS("deviceClass"))).text)
    ret += "<adept:deviceType>%s</adept:deviceType>" % (devicexml.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (devicexml.find("./%s" % (adNS("fingerprint"))).text)

    ret += "</adept:targetDevice>"

    ret += addNonce()

    ret += "<adept:user>%s</adept:user>" % (user_uuid)

    ret += "</adept:activate>"

    return ret

    

def activateDevice(): 

    activate_req = buildActivateReq()

    print("activate")
    print(activate_req)

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    req_xml = etree.fromstring(activate_req)

    print(req_xml)

    signature = sign_node(req_xml)

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    print ("final request:")
    print(etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))

    data = "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")

    ret = sendRequestDocu(data, VAR_ACS_SERVER + "/Activate")
    print(ret)




'''
    
    void DRMProcessor::activateDevice()
    {
	pugi::xml_document activateReq;

	GOUROU_LOG(INFO, "Activate device");

	buildActivateReq(activateReq);

	pugi::xml_node root = activateReq.select_node("adept:activate").node();

	std::string signature = signNode(root);

	root = activateReq.select_node("adept:activate").node();
	appendTextElem(root, "adept:signature", signature);

	pugi::xml_document activationDoc;
	user->readActivation(activationDoc);

	std::string activationURL = user->getProperty("//adept:activationURL");
	activationURL += "/Activate";
	
	ByteArray reply = sendRequest(activateReq, activationURL);

	pugi::xml_document activationToken;
	activationToken.load_buffer(reply.data(), reply.length());
	
	root = activationDoc.select_node("activationInfo").node();
	root.append_copy(activationToken.first_child());
	user->updateActivationFile(activationDoc);
    }

'''


def sign_node(node):

    sha_hash = hash_node(node)

    print("SHA1 HASH is " + sha_hash.hex())

    global devkey_bytes
    global pkcs12

    print("pkcs12 is")
    print(pkcs12)

    my_pkcs12 = base64.b64decode(pkcs12)

    pkcs_data = crypto.load_pkcs12(my_pkcs12, base64.b64encode(devkey_bytes))

    my_priv_key = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkcs_data.get_privatekey())

    print(my_priv_key)

    key = RSA.importKey(my_priv_key)
    cipherAC = PKCS1_v1_5.new(key)
    crypted_msg = cipherAC.encrypt(bytes(sha_hash))

    print("Encrypted SHA hash: " + str(crypted_msg))
    return base64.b64encode(crypted_msg)

    

def hash_node(node):

    hash_ctx = hashlib.sha1()
    hash_node_ctx(node, hash_ctx)
    return hash_ctx.digest()



ASN_NONE = 0
ASN_NS_TAG = 1
ASN_CHILD = 2
ASN_END_TAG = 3
ASN_TEXT = 4
ASN_ATTRIBUTE = 5

debug = False

def hash_node_ctx(node, hash_ctx):

    qtag = etree.QName(node.tag)

    hash_do_append_tag(hash_ctx, ASN_NS_TAG)
    hash_do_append_string(hash_ctx, qtag.namespace)
    hash_do_append_string(hash_ctx, qtag.localname)


    attrKeys = node.keys()
    attrKeys.sort()
    for attribute in attrKeys: 
        hash_do_append_tag(hash_ctx, ASN_ATTRIBUTE)
        hash_do_append_string(hash_ctx, "")
        hash_do_append_string(hash_ctx, attribute)  # "requestType"
        hash_do_append_string(hash_ctx, node.get(attribute))    # "initial"

    
    if (node.text is not None):
        hash_do_append_tag(hash_ctx, ASN_CHILD)
        hash_do_append_tag(hash_ctx, ASN_TEXT)
        hash_do_append_string(hash_ctx, node.text.strip()) 
        hash_do_append_tag(hash_ctx, ASN_END_TAG)
    else: 
        hash_do_append_tag(hash_ctx, ASN_CHILD)
        for child in node: 
            hash_node_ctx(child, hash_ctx)
        hash_do_append_tag(hash_ctx, ASN_END_TAG)


def hash_do_append_string(hash_ctx, string: str):
    length = len(string)
    len_upper = int(length / 256)
    len_lower = int(length & 0xFF)

    global debug

    if debug: 
        print("[STR %02x %02x => %s ]" % (len_upper, len_lower, string))

    hash_do_append_raw_bytes(hash_ctx, [len_upper, len_lower])
    hash_do_append_raw_bytes(hash_ctx, bytes(string, encoding="latin-1"))

def hash_do_append_tag(hash_ctx, tag: int):

    global debug

    if debug: 
        if (tag == ASN_NONE):
            print("[TAG ASN_NONE (0) ]")
        elif (tag == ASN_NS_TAG):
            print("[TAG ASN_NS_TAG (1) ]")
        elif (tag == ASN_CHILD):
            print("[TAG ASN_CHILD (2) ]")
        elif (tag == ASN_END_TAG):
            print("[TAG ASN_END_TAG (3) ]")
        elif (tag == ASN_TEXT):
            print("[TAG ASN_TEXT (4) ]")
        elif (tag == ASN_ATTRIBUTE):
            print("[TAG ASN_ATTRIBUTE (5) ]")
        else: 
            print("[ INVALID TAG!!!! %d" % (tag))

    if (tag > 5):
        return
    
    hash_do_append_raw_bytes(hash_ctx, [tag])

def hash_do_append_raw_bytes(hash_ctx, data: bytes):
    hash_ctx.update(bytearray(data))






def main():
    createDevice()
    createUser()

    signIn(VAR_MAIL, VAR_PASS)
    activateDevice()


if __name__ == "__main__":
    main()