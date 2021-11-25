from lxml import etree
import base64
import os, locale, platform

try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.asn1 import DerSequence
    from Crypto.Cipher import PKCS1_v1_5
except ImportError:
    # Debian (and Ubuntu) ship pycryptodome, but not in its compatible mode with pycrypto
    # If `Crypto` can't be found, try under pycryptodome's own namespace
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Util.asn1 import DerSequence
    from Cryptodome.Cipher import PKCS1_v1_5

try: 
    from libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
    from libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key
    from libadobe import get_devkey_path, get_device_path, get_activation_xml_path
    from libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS, VAR_VER_OS_IDENTIFIERS
    from libadobe import VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO, VAR_VER_SUPP_VERSIONS, VAR_ACS_SERVER_HTTP
    from libadobe import VAR_ACS_SERVER_HTTPS, VAR_VER_BUILD_IDS, VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT, VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE
except: 
    from calibre_plugins.deacsm.libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
    from calibre_plugins.deacsm.libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key
    from calibre_plugins.deacsm.libadobe import get_devkey_path, get_device_path, get_activation_xml_path
    from calibre_plugins.deacsm.libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS, VAR_VER_OS_IDENTIFIERS
    from calibre_plugins.deacsm.libadobe import VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO, VAR_VER_SUPP_VERSIONS, VAR_ACS_SERVER_HTTP
    from calibre_plugins.deacsm.libadobe import VAR_ACS_SERVER_HTTPS, VAR_VER_BUILD_IDS, VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT, VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE



def createDeviceFile(randomSerial: bool, useVersionIndex: int = 0): 
    # Original implementation: Device::createDeviceFile(const std::string& hobbes, bool randomSerial)

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        # ADE 1.7.2 or another version that authorization is disabled for
        return False

    serial = makeSerial(randomSerial)
    fingerprint = makeFingerprint(serial)

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "deviceInfo"))
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceType")).text = "standalone"

    # These three elements are not supposed to be sent to Adobe:
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceClass")).text = "Desktop"
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceSerial")).text = serial
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceName")).text = platform.uname()[1]
    # ##

    atr_ver = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver.set("name", "hobbes")
    atr_ver.set("value", VAR_VER_HOBBES_VERSIONS[useVersionIndex])

    atr_ver2 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver2.set("name", "clientOS")

    # This used to contain code to actually read the user's operating system. 
    # That's probably not a good idea because then Adobe sees a bunch of requests from "Linux"
    #atr_ver2.set("value", platform.system() + " " + platform.release())
    atr_ver2.set("value", VAR_VER_OS_IDENTIFIERS[useVersionIndex])

    atr_ver3 = etree.SubElement(root, etree.QName(NSMAP["adept"], "version"))
    atr_ver3.set("name", "clientLocale")

    language = None
    try: 
        language = locale.getdefaultlocale()[0].split('_')[0]
    except:
        pass
    if language is None or language == "": 
        # Can sometimes happen on MacOS with default English language
        language = "en"

    atr_ver3.set("value", language)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "fingerprint")).text = fingerprint

    f = open(get_device_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()

    return True


def createUser(useVersionIndex: int = 0): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }

    root = etree.Element("activationInfo")
    root.set("xmlns", NSMAP["adept"])

    etree.register_namespace("adept", NSMAP["adept"])

    activationServiceInfo = etree.SubElement(root, etree.QName(NSMAP["adept"], "activationServiceInfo"))

    useHTTPS = False
    if VAR_VER_BUILD_IDS[useVersionIndex] >= VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT:
        useHTTPS = True


    if useHTTPS:
        # ADE 4.X uses HTTPS
        activationURL = VAR_ACS_SERVER_HTTPS + "/ActivationServiceInfo"
    else:
        activationURL = VAR_ACS_SERVER_HTTP + "/ActivationServiceInfo"

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
    if useHTTPS:
        # ADE 4.X uses HTTPS
        etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER_HTTPS
    else: 
        etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER_HTTP
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
            elif ("E_AUTH_FAILED" in err and "LOGIN_FAILED" in err): 
                return False, "E_AUTH_FAILED/LOGIN_FAILED. If you have 2FA enabled, please disable that and try again."
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



def buildActivateReq(useVersionIndex: int = 0): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        # ADE 1.7.2 or another version that authorization is disabled for
        return False

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
        return False, "Required version information missing"
        
    ret = ""

    ret += "<?xml version=\"1.0\"?>"
    ret += "<adept:activate xmlns:adept=\"http://ns.adobe.com/adept\" requestType=\"initial\">"
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (devicexml.find("./%s" % (adNS("fingerprint"))).text)
    ret += "<adept:deviceType>%s</adept:deviceType>" % (devicexml.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (VAR_VER_SUPP_VERSIONS[useVersionIndex])
    ret += "<adept:targetDevice>"


    ret += "<adept:softwareVersion>%s</adept:softwareVersion>" % (version)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (VAR_VER_SUPP_VERSIONS[useVersionIndex])
    ret += "<adept:deviceType>%s</adept:deviceType>" % (devicexml.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:productName>%s</adept:productName>" % ("ADOBE Digitial Editions")
    # YES, this typo ("Digitial" instead of "Digital") IS present in ADE!!

    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (devicexml.find("./%s" % (adNS("fingerprint"))).text)

    ret += "</adept:targetDevice>"

    ret += addNonce()

    ret += "<adept:user>%s</adept:user>" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)

    ret += "</adept:activate>"

    return True, ret


# Call this function to change from ADE2 to ADE3 and vice versa.
def changeDeviceVersion(useVersionIndex: int = 0):
    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index"

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False, "Unknown build ID"

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO:
        # A version that we no longer want to allow switching to
        return False, "BuildID not supported"

    try: 
        devicexml = etree.parse(get_device_path())
        new_hobbes = VAR_VER_HOBBES_VERSIONS[useVersionIndex]
        new_os = VAR_VER_OS_IDENTIFIERS[useVersionIndex]
    except: 
        return False, "Error preparing version change"

    
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    ver = devicexml.findall("./%s" % (adNS("version")))

    for f in ver:
        if f.get("name") == "hobbes":
            #print("Changing hobbes from {0} to {1}".format(f.attrib["value"], new_hobbes))
            f.attrib["value"] = new_hobbes
        if f.get("name") == "clientOS":
            #print("Changing OS from {0} to {1}".format(f.attrib["value"], new_os))
            f.attrib["value"] = new_os

    try: 
        f = open(get_device_path(), "w")
        f.write("<?xml version=\"1.0\"?>\n")
        f.write(etree.tostring(devicexml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
        f.close()
    except: 
        return False, "Failed to update device file."

    return True, ""
        


def activateDevice(useVersionIndex: int = 0): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index"

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False, "error checking build ID"

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        # ADE 1.7.2 or another version that authorization is disabled for
        return False, "Authorization not supported for this build ID"

    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        deacsmprefs = prefs.DeACSM_Prefs()
        verbose_logging = deacsmprefs["detailed_logging"]
    except:
        pass


    result, activate_req = buildActivateReq(useVersionIndex)
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

    if verbose_logging:
        print ("Activation request:")
        print(etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))

    data = "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")

    useHTTPS = False
    if VAR_VER_BUILD_IDS[useVersionIndex] >= VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT:
        useHTTPS = True

    if useHTTPS:
        # ADE 4.X uses HTTPS
        ret = sendRequestDocu(data, VAR_ACS_SERVER_HTTPS + "/Activate")
    else:
        ret = sendRequestDocu(data, VAR_ACS_SERVER_HTTP + "/Activate")

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
   
    if verbose_logging:
        print("Response from server: ")
        print(ret)

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

def getAccountUUID():
    try:
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

        if not user_uuid.startswith("urn:uuid:"):
            return None

        return user_uuid[9:]
    except: 
        return None


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

def exportAccountEncryptionKeyBytes():
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        privatekey = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("privateLicenseKey"))).text
        privatekey = base64.b64decode(privatekey)
        privatekey = privatekey[26:]
        return privatekey
    except: 
        return None