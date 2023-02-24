
'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

from lxml import etree
import base64
import locale, platform

try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Util.asn1 import DerSequence
    from Cryptodome.Cipher import PKCS1_v1_5
except ImportError:
    # Some distros ship this as Crypto still.
    from Crypto.PublicKey import RSA
    from Crypto.Util.asn1 import DerSequence
    from Crypto.Cipher import PKCS1_v1_5

#@@CALIBRE_COMPAT_CODE@@


from libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
from libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key
from libadobe import get_devkey_path, get_device_path, get_activation_xml_path
from libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS, VAR_VER_OS_IDENTIFIERS
from libadobe import VAR_VER_ALLOWED_BUILD_IDS_SWITCH_TO, VAR_VER_SUPP_VERSIONS, VAR_ACS_SERVER_HTTP
from libadobe import VAR_ACS_SERVER_HTTPS, VAR_VER_BUILD_IDS, VAR_VER_NEED_HTTPS_BUILD_ID_LIMIT, VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE


def createDeviceFile(randomSerial, useVersionIndex = 0): 
    # type: (bool, int) -> bool

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

def getAuthMethodsAndCert():
    # Queries the /AuthenticationServiceInfo endpoint to get a list
    # of available ID providers. 
    # Returns a list of providers, and the login certificate. 

    # The login certificate stuff would usually be handled elsewhere,
    # but that would require another request to Adobe's servers
    # which is not what we want (as ADE only performs one request, too),
    # so we need to store this cert.

    # If you DO call this method before calling createUser, 
    # it is your responsibility to pass the authCert returned by this function
    # to the createUser function call. 
    # Otherwise the plugin will not look 100% like ADE to Adobe.

    authenticationURL = VAR_ACS_SERVER_HTTP + "/AuthenticationServiceInfo"
    response2 = sendHTTPRequest(authenticationURL)

    adobe_response_xml2 = etree.fromstring(response2)

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    try: 
        authCert = None
        authCert = adobe_response_xml2.find("./%s" % (adNS("certificate"))).text
    except:
        pass

    # Get sign-in methods.
    sign_in_methods = adobe_response_xml2.findall("./%s/%s" % (adNS("signInMethods"), adNS("signInMethod")))

    aid_ids = []
    aid_names = []

    for method in sign_in_methods:
        mid = method.get("method", None)
        txt = method.text

        if mid != "anonymous":
            aid_ids.append(mid)
            aid_names.append(txt)

    return [aid_ids, aid_names], authCert




def createUser(useVersionIndex = 0, authCert = None): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index", [[], []]

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
        return False, "Error: Unexpected reply from Adobe.", [[], []]

    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authURL")).text = authURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "userInfoURL")).text = userInfoURL
    if useHTTPS:
        # ADE 4.X uses HTTPS
        etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER_HTTPS
    else: 
        etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER_HTTP
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "certificate")).text = certificate


    if authCert is None: 
        # This is not supposed to happen, but if it does, then just query it again from Adobe.
        authenticationURL = authURL + "/AuthenticationServiceInfo"
        response2 = sendHTTPRequest(authenticationURL)

        adobe_response_xml2 = etree.fromstring(response2)
        authCert = adobe_response_xml2.find("./%s" % (adNS("certificate"))).text


    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authenticationCertificate")).text = authCert


    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()

    return True, "Done"

def encryptLoginCredentials(username, password, authenticationCertificate): 
    # type: (str, str, str) -> bytes

    from libadobe import devkey_bytes as devkey_adobe
    import struct

    if devkey_adobe is not None: 
        devkey_bytes = devkey_adobe
    else: 
        f = open(get_devkey_path(), "rb")
        devkey_bytes = f.read()
        f.close()

    _authenticationCertificate = base64.b64decode(authenticationCertificate)

    # Build buffer <devkey_bytes> <len username> <username> <len password> <password>

    ar = bytearray(devkey_bytes)
    ar.extend(bytearray(struct.pack("B", len(username))))
    ar.extend(bytearray(username.encode("latin-1")))
    ar.extend(bytearray(struct.pack("B", len(password))))
    ar.extend(bytearray(password.encode("latin-1")))

    # Crypt code from https://stackoverflow.com/a/12921889/4991648
    cert = DerSequence()
    cert.decode(_authenticationCertificate)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]

    rsakey = RSA.importKey(subjectPublicKeyInfo)
    cipherAC = PKCS1_v1_5.new(rsakey)
    crypted_msg = cipherAC.encrypt(bytes(ar))

    return crypted_msg


def buildSignInRequestForAnonAuthConvert(username, password, authenticationCertificate):
    # type: (str, str, str) -> str

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "signIn"))
    root.set("method", "AdobeID")

    crypted_msg = encryptLoginCredentials(username, password, authenticationCertificate)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "signInData")).text = base64.b64encode(crypted_msg)

    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    except: 
        return None

    # Note: I tried replacing the user_uuid with the UUID of another (anonymous) authorization
    # to see if it was possible to take over another account, but that didn't work. That's the reason
    # why this request has the signature node, the payload needs to be signed with the user certificate
    # that matches the UUID in the <adept:user> tag.

    etree.SubElement(root, etree.QName(NSMAP["adept"], "user")).text = user_uuid
    signature = sign_node(root)
    etree.SubElement(root, etree.QName(NSMAP["adept"], "signature")).text = signature

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1")


def buildSignInRequest(type, username, password, authenticationCertificate):
    # type: (str, str, str, str) -> str

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "signIn"))
    root.set("method", type)

    crypted_msg = encryptLoginCredentials(username, password, authenticationCertificate)

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
    

def convertAnonAuthToAccount(username, passwd):

    # If you have an anonymous authorization, you can convert that to an AdobeID. 
    # Important: You can only do this ONCE for each AdobeID. 
    # The AdobeID you are using for this must not be connected to any ADE install.

    # This is intended for cases where people install ADE, use an anonymous auth, 
    # buy a couple books, and then decide to get a fresh AdobeID.

    # Get authenticationCertificate
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        authenticationCertificate = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authenticationCertificate"))).text
    except: 
        return False, "Missing authenticationCertificate"

    if authenticationCertificate == "":
        return False, "Empty authenticationCertificate"

    linkRequest = buildSignInRequestForAnonAuthConvert(username, passwd, authenticationCertificate)
    signInURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text + "/AddSignInDirect"
    linkResponse = sendRequestDocu(linkRequest, signInURL)

    try: 
        credentialsXML = etree.fromstring(linkResponse)
        
        if (credentialsXML.tag == adNS("error")): 
            err = credentialsXML.get("data")
            err_parts = err.split(' ')
            if err_parts[0] == "E_AUTH_USER_ALREADY_REGISTERED": 
                # This error happens when you're not using a "fresh" AdobeID. 
                # The AdobeID already has an UUID and authentication data, thus
                # it cannot be set up using the data from the anonymous authorization.
                try: 
                    return False, "Can't link anon auth " + err_parts[2] + " to account, account already has user ID " + err_parts[3]
                except: 
                    pass
            
            elif err_parts[0] == "E_AUTH_USERID_INUSE":
                # This error happens when the UUID of the anonymous auth is already 
                # in use by a given AdobeID. 
                # This can happen if you have one anonymous auth, export that, 
                # then convert it to AdobeID A, then re-import the backed-up anonymous auth
                # (or use another computer that has the identical cloned anonymous auth)
                # and then try to link that auth to another AdobeID B. 
                # Adobe then notices that the anonymous authorization you're trying to link
                # has already been linked to an Adobe account. 
                try: 
                    return False, "Can't link anon auth: Anon auth " + err_parts[3] + " has already been linked to another AdobeID"
                except:
                    pass
            
            return False, "Can't link anon auth to account: " + err

        elif (credentialsXML.tag != adNS("success")):
            return False, "Invalid main tag " + credentialsXML.tag
    except: 
        return False, "Invalid response to login request"


    # If we end up here, the account linking was successful. Now we just need to update the activation.xml accordingly.

    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    cred_node = activationxml.find("./%s" % (adNS("credentials")))


    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    tmp_node = etree.SubElement(cred_node, etree.QName(NSMAP["adept"], "username"))

    # Adobe / ADE only supports this account linking for AdobeID accounts, not for any Vendor IDs.
    tmp_node.set("method", "AdobeID")
    tmp_node.text = username

    # Write to file
    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("latin-1"))
    f.close()

    
    return True, "Account linking successful"




def signIn(account_type, username, passwd):


    # Get authenticationCertificate
    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    authenticationCertificate = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authenticationCertificate"))).text

    
    # Type = "AdobeID" or "anonymous". For "anonymous", username and passwd need to be the empty string.
    signInRequest = buildSignInRequest(account_type, username, passwd, authenticationCertificate)

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
    if account_type != "anonymous": 
        f.write("<adept:username method=\"%s\">%s</adept:username>\n" % (credentialsXML.find("./%s" % (adNS("username"))).get("method", account_type), credentialsXML.find("./%s" % (adNS("username"))).text))
    f.write("<adept:pkcs12>%s</adept:pkcs12>\n" % (credentialsXML.find("./%s" % (adNS("pkcs12"))).text))
    f.write("<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (credentialsXML.find("./%s" % (adNS("licenseCertificate"))).text))
    f.write("<adept:privateLicenseKey>%s</adept:privateLicenseKey>\n" % (base64.b64encode(private_key_data).decode("latin-1")))
    f.write("<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (authenticationCertificate))
    f.write("</adept:credentials>\n")
    f.write("</activationInfo>\n")

    f.close()

    return True, "Done"

def exportProxyAuth(act_xml_path, activationToken):
    # This authorizes a tethered device. 
    # ret, data = exportProxyAuth(act_xml_path, data)

    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # At some point I should probably rewrite this, but I want to be sure the format is
    # correct so I'm recreating the whole XML myself.

    rt_si_authURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text
    rt_si_userInfoURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("userInfoURL"))).text
    rt_si_activationURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("activationURL"))).text
    rt_si_certificate = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("certificate"))).text

    rt_c_user = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    rt_c_licenseCertificate = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("licenseCertificate"))).text
    rt_c_privateLicenseKey = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("privateLicenseKey"))).text
    rt_c_authenticationCertificate = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("authenticationCertificate"))).text

    rt_c_username = None
    rt_c_usernameMethod = None

    try: 
        rt_c_username = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("username"))).text
        rt_c_usernameMethod = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("username"))).get("method", "AdobeID")
    except:
        pass

    
    ret = "<?xml version=\"1.0\"?>"
    ret += "<activationInfo xmlns=\"http://ns.adobe.com/adept\">"
    ret += "<adept:activationServiceInfo xmlns:adept=\"http://ns.adobe.com/adept\">"
    ret += "<adept:authURL>%s</adept:authURL>" % (rt_si_authURL)
    ret += "<adept:userInfoURL>%s</adept:userInfoURL>" % (rt_si_userInfoURL)
    ret += "<adept:activationURL>%s</adept:activationURL>" % (rt_si_activationURL)
    ret += "<adept:certificate>%s</adept:certificate>" % (rt_si_certificate)
    ret += "</adept:activationServiceInfo>"

    ret += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">"
    ret += "<adept:user>%s</adept:user>" % (rt_c_user)
    ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>" % (rt_c_licenseCertificate)
    ret += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>" % (rt_c_privateLicenseKey)
    ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (rt_c_authenticationCertificate)

    if rt_c_username is not None: 
        ret += "<adept:username method=\"%s\">%s</adept:username>" % (rt_c_usernameMethod, rt_c_username)

    ret += "</adept:credentials>"

    activationToken = activationToken.decode("latin-1")
    # Yeah, terrible hack, but Adobe sends the token with namespace but exports it without.
    activationToken = activationToken.replace(' xmlns="http://ns.adobe.com/adept"', '')

    ret += activationToken

    ret += "</activationInfo>"

    # Okay, now we can finally write this to the device. 

    try: 
        f = open(act_xml_path, "w")
        f.write(ret)
        f.close()
    except: 
        return False, "Can't write file"

    return True, "Done"
    






def buildActivateReqProxy(useVersionIndex = 0, proxyData = None):

    if proxyData is None: 
        return False

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        # ADE 1.7.2 or another version that authorization is disabled for
        return False

    local_device_xml = etree.parse(get_device_path())
    local_activation_xml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    version = None
    clientOS = None
    clientLocale = None

    ver = local_device_xml.findall("./%s" % (adNS("version")))


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
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (proxyData.find("./%s" % (adNS("fingerprint"))).text)
    ret += "<adept:deviceType>%s</adept:deviceType>" % (proxyData.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (VAR_VER_SUPP_VERSIONS[useVersionIndex])

    ret += "<adept:proxyDevice>"
    ret += "<adept:softwareVersion>%s</adept:softwareVersion>" % (version)
    ret += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    ret += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (VAR_VER_SUPP_VERSIONS[useVersionIndex])
    ret += "<adept:deviceType>%s</adept:deviceType>" % (local_device_xml.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:productName>%s</adept:productName>" % ("ADOBE Digitial Editions")
    # YES, this typo ("Digitial" instead of "Digital") IS present in ADE!!

    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (local_device_xml.find("./%s" % (adNS("fingerprint"))).text)

    ret += "<adept:activationToken>"
    ret += "<adept:user>%s</adept:user>" % (local_activation_xml.find("./%s/%s" % (adNS("activationToken"), adNS("user"))).text)
    ret += "<adept:device>%s</adept:device>" % (local_activation_xml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text)
    ret += "</adept:activationToken>"
    ret += "</adept:proxyDevice>"

    ret += "<adept:targetDevice>"

    target_hobbes_vers = proxyData.findall("./%s" % (adNS("version")))
    hobbes_version = None
    for f in target_hobbes_vers:
        if f.get("name") == "hobbes":
            hobbes_version = f.get("value")
            break

    if hobbes_version is not None:
        ret += "<adept:softwareVersion>%s</adept:softwareVersion>" % (hobbes_version)
    
    ret += "<adept:clientVersion>%s</adept:clientVersion>" % (proxyData.find("./%s" % (adNS("deviceClass"))).text)
    ret += "<adept:deviceType>%s</adept:deviceType>" % (proxyData.find("./%s" % (adNS("deviceType"))).text)
    ret += "<adept:productName>%s</adept:productName>" % ("ADOBE Digitial Editions")
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (proxyData.find("./%s" % (adNS("fingerprint"))).text)


    ret += "</adept:targetDevice>"

    ret += addNonce()

    ret += "<adept:user>%s</adept:user>" % (local_activation_xml.find("./%s/%s" % (adNS("activationToken"), adNS("user"))).text)

    ret += "</adept:activate>"

    return True, ret


def buildActivateReq(useVersionIndex = 0): 

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

    # TODO: Here's where multiple <adept:activationToken>s, each with a user and a device,
    # TODO: would show up if the client was already activated and just adds an additional activation.
    # TODO: Not sure if I want to replicate this, or if I'd rather replicate independant installations ...

    ret += "</adept:targetDevice>"

    ret += addNonce()

    ret += "<adept:user>%s</adept:user>" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)

    ret += "</adept:activate>"

    return True, ret


# Call this function to change from ADE2 to ADE3 and vice versa.
def changeDeviceVersion(useVersionIndex = 0):
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
        


def activateDevice(useVersionIndex = 0, proxyData = None): 

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
        deacsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = deacsmprefs["detailed_logging"]
    except:
        pass

    if proxyData is not None:
        result, activate_req = buildActivateReqProxy(useVersionIndex, proxyData)
    else:
        result, activate_req = buildActivateReq(useVersionIndex)
    if (result is False):
        return False, "Building activation request failed: " + activate_req


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

    if proxyData is not None: 
        # If we have a proxy device, this function doesn't know where to store the activation.
        # Just return the data and have the caller figure that out.
        return True, ret

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


def exportAccountEncryptionKeyDER(output_file):
    # type: (str) -> bool
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