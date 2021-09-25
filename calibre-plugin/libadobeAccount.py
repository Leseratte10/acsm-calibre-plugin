from lxml import etree
import base64
import os, locale, platform

from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from Crypto.Cipher import PKCS1_v1_5

try: 
    from libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
    from libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key
    from libadobe import get_devkey_path, get_device_path, get_activation_xml_path
except: 
    from calibre_plugins.deacsm.libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
    from calibre_plugins.deacsm.libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key
    from calibre_plugins.deacsm.libadobe import get_devkey_path, get_device_path, get_activation_xml_path


VAR_AUTH_SERVER = "adeactivate.adobe.com"
VAR_ACS_SERVER = "http://adeactivate.adobe.com/adept"
VAR_HOBBES_VERSION = "10.0.4"


def createDeviceFile(hobbes: str, randomSerial: bool): 
    # Original implementation: Device::createDeviceFile(const std::string& hobbes, bool randomSerial)
    serial = makeSerial(randomSerial)
    fingerprint = makeFingerprint(serial)

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "deviceInfo"))
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceClass")).text = "Desktop"
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceSerial")).text = serial
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceName")).text = platform.uname()[1]
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceType")).text = "standalone"

    atr_ver = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver.set("name", "hobbes")
    atr_ver.set("value", hobbes)

    atr_ver2 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver2.set("name", "clientOS")
    atr_ver2.set("value", platform.system() + " " + platform.release())
    # "Windows Vista"

    atr_ver3 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver3.set("name", "clientLocale")
    atr_ver3.set("value", locale.getdefaultlocale()[0])

    etree.SubElement(root, etree.QName(NSMAP["adept"], "fingerprint")).text = fingerprint

    f = open(get_device_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()


def createUser(): 

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }

    root = etree.Element("activationInfo")
    root.set("xmlns", NSMAP["adept"])

    etree.register_namespace("adept", NSMAP["adept"])

    activationServiceInfo = etree.SubElement(root, etree.QName(NSMAP["adept"], "activationServiceInfo"))

    
    activationURL = VAR_ACS_SERVER + "/ActivationServiceInfo"
    response = sendHTTPRequest(activationURL)

    #print("======================================================")
    #print("Sending request to " + activationURL)
    #print("got response:")
    #print(response)
    #print("======================================================")

    adobe_response_xml = etree.fromstring(response)

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    authURL = adobe_response_xml.find("./%s" % (adNS("authURL"))).text
    userInfoURL = adobe_response_xml.find("./%s" % (adNS("userInfoURL"))).text
    certificate = adobe_response_xml.find("./%s" % (adNS("certificate"))).text

    if (authURL is None or userInfoURL is None or certificate is None):
        return False, "Error: Unexpected reply from Adobe."

    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authURL")).text = authURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "userInfoURL")).text = userInfoURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "certificate")).text = certificate


    authenticationURL = authURL + "/AuthenticationServiceInfo"
    response2 = sendHTTPRequest(authenticationURL)

    #print("======================================================")
    #print("Sending request to " + authenticationURL)
    #print("got response:")
    #print(response2)
    #print("======================================================")

    adobe_response_xml2 = etree.fromstring(response2)
    authCert = adobe_response_xml2.find("./%s" % (adNS("certificate"))).text
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authenticationCertificate")).text = authCert


    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()
    return True, "Done"




def buildSignInRequest(adobeID: str, adobePassword: str, authenticationCertificate: str):
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "signIn"))
    root.set("method", "AdobeID")

    f = open(get_devkey_path(), "rb")
    devkey_bytes = f.read()
    f.close()

    _authenticationCertificate = base64.b64decode(authenticationCertificate)

    # Build buffer <devkey_bytes> <len username> <username> <len password> <password>

    ar = bytearray(devkey_bytes)
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

    etree.SubElement(root, etree.QName(NSMAP["adept"], "signInData")).text = base64.b64encode(crypted_msg)

    # Generate Auth key and License Key
    authkey = RSA.generate(1024, e=65537)
    licensekey = RSA.generate(1024, e=65537)

    authkey_pub = authkey.publickey().exportKey("DER")
    authkey_priv = authkey.exportKey("DER", pkcs=8)
    authkey_priv_enc = encrypt_with_device_key(authkey_priv) 

    licensekey_pub = licensekey.publickey().exportKey("DER")
    licensekey_priv = licensekey.exportKey("DER", pkcs=8)
    licensekey_priv_enc = encrypt_with_device_key(licensekey_priv) 


    etree.SubElement(root, etree.QName(NSMAP["adept"], "publicAuthKey")).text = base64.b64encode(authkey_pub)
    etree.SubElement(root, etree.QName(NSMAP["adept"], "encryptedPrivateAuthKey")).text = base64.b64encode(authkey_priv_enc)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "publicLicenseKey")).text = base64.b64encode(licensekey_pub)
    etree.SubElement(root, etree.QName(NSMAP["adept"], "encryptedPrivateLicenseKey")).text = base64.b64encode(licensekey_priv_enc)

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")
    


def signIn(username: str, passwd: str):


    # Get authenticationCertificate
    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    authenticationCertificate = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authenticationCertificate"))).text

    signInRequest = buildSignInRequest(username, passwd, authenticationCertificate)

    signInURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text + "/SignInDirect"

    credentials = sendRequestDocu(signInRequest, signInURL)
    
    
    #print("======================================================")
    #print("Sending request to " + signInURL)
    #print("Payload:")
    #print(signInRequest)
    #print("got response:")
    #print(credentials)
    #print("======================================================")


    try: 
        credentialsXML = etree.fromstring(credentials)
        
        if (credentialsXML.tag == adNS("error")): 
            err = credentialsXML.get("data")
            if ("E_AUTH_FAILED" in err and "CUS05051" in err): 
                return False, "Invalid username or password!"
            else: 
                return False, "Unknown Adobe error:" + credentials
            
        elif (credentialsXML.tag == adNS("credentials")):
            pass
            #print("Login successful")
        else: 
            return False, "Invalid main tag " + credentialsXML.tag

    
    except: 
        return False, "Invalid response to login request"

    # Got correct credentials

    private_key_data_encrypted = credentialsXML.find("./%s" % (adNS("encryptedPrivateLicenseKey"))).text
    private_key_data_encrypted = base64.b64decode(private_key_data_encrypted)
    private_key_data = decrypt_with_device_key(private_key_data_encrypted)


    # Okay, now we got the credential response correct. Now "just" apply all these to the main activation.xml

    f = open(get_activation_xml_path(), "w")

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

    return True, "Done"



def buildActivateReq(): 

    devicexml = etree.parse(get_device_path())
    activationxml = etree.parse(get_activation_xml_path())
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
        return False, "err"
        
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

    ret += "<adept:user>%s</adept:user>" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)

    ret += "</adept:activate>"

    return True, ret


def activateDevice(): 

    result, activate_req = buildActivateReq()
    if (result is False):
        return False, "Building activation request failed: " + activate_req

    #print("======================================================")
    #print("activate")
    #print(activate_req)

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    req_xml = etree.fromstring(activate_req)

    signature = sign_node(req_xml)

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    #print ("final request:")
    #print(etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))

    data = "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")

    ret = sendRequestDocu(data, VAR_ACS_SERVER + "/Activate")

    try: 
        credentialsXML = etree.fromstring(ret)
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)


        if (credentialsXML.tag == adNS("error")): 
            err = credentialsXML.get("data")
            return False, "Adobe error: " + err.split(' ')[0] + "\n" + err
            
        elif (credentialsXML.tag == adNS("activationToken")):
            pass
            #print("Login successful")
        else: 
            return False, "Invalid main tag " + credentialsXML.tag
    except: 
        return False, "Error parsing Adobe /Activate response"
   
    #print("Response from server: ")
    #print(ret)

    # Soooo, lets go and append that to the XML: 
    
    f = open(get_activation_xml_path(), "r")
    old_xml = f.read().replace("</activationInfo>", "")
    f.close()
    
    f = open(get_activation_xml_path(), "w")

    f.write(old_xml)
    f.write(ret.decode("latin-1"))
    f.write("</activationInfo>\n")
    f.close()

    return True, ret    

def exportAccountEncryptionKeyDER(output_file: str):
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        privatekey = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("privateLicenseKey"))).text
        privatekey = base64.b64decode(privatekey)
        privatekey = privatekey[26:]

        f = open(output_file, "wb")
        f.write(privatekey)
        f.close()
        return True
    except: 
        return False
