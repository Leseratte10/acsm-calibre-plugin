
'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

from lxml import etree
import base64
import locale, warnings
from xml.sax.saxutils import escape as xml_escape

try:
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Util.asn1 import DerSequence
    from Cryptodome.Cipher import PKCS1_v1_5
except ImportError:
    # Some distros ship this as Crypto still.
    from Crypto.PublicKey import RSA
    from Crypto.Util.asn1 import DerSequence
    from Crypto.Cipher import PKCS1_v1_5


from .libadobe import addNonce, sign_node, sendRequestDocu, sendHTTPRequest
from .libadobe import makeFingerprint, makeSerial, encrypt_with_device_key, decrypt_with_device_key, get_device_name
from .libadobe import get_devkey_path, get_device_path, get_activation_xml_path
from .libadobe import VAR_VER_SUPP_CONFIG_NAMES, VAR_VER_HOBBES_VERSIONS, VAR_VER_OS_IDENTIFIERS
from .libadobe import VAR_VER_SUPP_VERSIONS
from .libadobe import VAR_ACS_SERVER_HTTPS, VAR_VER_BUILD_IDS, VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE
from .libadobe import safe_xml_parser, write_file_atomically
from .libadobe import find_vendor_values, prefer_vendor


def createDeviceFile(randomSerial, useVersionIndex = 0): 
    # type: (bool, int) -> bool

    # Original implementation: Device::createDeviceFile(const std::string& hobbes, bool randomSerial)

    if useVersionIndex is None: 
        return False
    
    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False

    build_id = VAR_VER_BUILD_IDS[useVersionIndex]

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        return False

    serial = makeSerial(randomSerial)
    fingerprint = makeFingerprint(serial)

    write_file_atomically(get_device_path(), build_device_xml("standalone", serial, fingerprint, useVersionIndex))

    return True


def build_device_xml(device_type, serial, fingerprint, useVersionIndex = 0):
    # type: (str, str, str, int) -> bytes
    # Returns the content of device.xml. A new authorization (createDeviceFile) and the
    # imports from Digital Editions all create it with this, so the files can't drift apart.
    # Raises ValueError if a value contains characters that XML doesn't allow.

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    root = etree.Element(etree.QName(NSMAP["adept"], "deviceInfo"))
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceType")).text = device_type

    # These three elements are not supposed to be sent to Adobe:
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceClass")).text = "Desktop"
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceSerial")).text = serial
    etree.SubElement(root, etree.QName(NSMAP["adept"], "deviceName")).text = get_device_name()
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
        with warnings.catch_warnings():
            # Python claims that this is deprecated, but it has been un-deprecated later.
            # Disable the warning.
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            language = locale.getdefaultlocale()[0].split('_')[0]
    except:
        pass
    if language is None or language == "": 
        # Can sometimes happen on MacOS with default English language
        language = "en"

    atr_ver3.set("value", language)

    etree.SubElement(root, etree.QName(NSMAP["adept"], "fingerprint")).text = fingerprint

    return b"<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False)

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

    authenticationURL = VAR_ACS_SERVER_HTTPS + "/AuthenticationServiceInfo?ofByteBooks=1"
    response2 = sendHTTPRequest(authenticationURL, True)

    adobe_response_xml2 = etree.fromstring(response2, parser=safe_xml_parser())

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    authCert_bb, authCert_adobe = find_vendor_values(adobe_response_xml2, "certificate")

    # Get sign-in methods.
    sign_in_methods = adobe_response_xml2.findall("./%s/%s" % (adNS("signInMethods"), adNS("signInMethod")))

    aid_ids = []
    aid_names = []

    for method in sign_in_methods:
        mid = method.get("method", None)
        txt = method.text

        if mid == "anonymous":
            continue
        elif mid == "AdobeID":
            aid_ids.append(mid)
            aid_names.append("ByteBooks ID (Adobe ID)")
        else:
            aid_ids.append(mid)
            aid_names.append(txt)

    return [aid_ids, aid_names], authCert_bb, authCert_adobe




def createUser(useVersionIndex = 0, authCertBB = None, authCertAdobe = None): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }

    root = etree.Element("activationInfo")
    root.set("xmlns", NSMAP["adept"])

    etree.register_namespace("adept", NSMAP["adept"])

    activationServiceInfo = etree.SubElement(root, etree.QName(NSMAP["adept"], "activationServiceInfo"))

    activationURL = VAR_ACS_SERVER_HTTPS + "/ActivationServiceInfo?ofByteBooks=1"

    response = sendHTTPRequest(activationURL, True)

    #print("======================================================")
    #print("Sending request to " + activationURL)
    #print("got response:")
    #print(response)
    #print("======================================================")

    adobe_response_xml = etree.fromstring(response, parser=safe_xml_parser())

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # findtext() returns None for a missing element, so an incomplete reply ends up in the
    # check below instead of raising (which the GUI reports as a connection problem).
    authURL = adobe_response_xml.findtext("./%s" % (adNS("authURL")))
    userInfoURL = adobe_response_xml.findtext("./%s" % (adNS("userInfoURL")))
    certificate_bb, certificate_adobe = find_vendor_values(adobe_response_xml, "certificate")

    if (not authURL or not userInfoURL or not certificate_bb):
        return False, "Error: Unexpected reply from activation service."

    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authURL")).text = authURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "userInfoURL")).text = userInfoURL
    etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "activationURL")).text = VAR_ACS_SERVER_HTTPS

    certbb = etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "certificate"))
    certbb.set("ofByteBooks", "true")
    certbb.text = certificate_bb

    if certificate_adobe is not None:
        certadobe = etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "certificate"))
        certadobe.set("ofByteBooks", "false")
        certadobe.text = certificate_adobe


    if authCertBB is None: 
        # This is not supposed to happen, but if it does, then just query it again from Adobe.
        authenticationURL = authURL + "/AuthenticationServiceInfo?ofByteBooks=1"
        response2 = sendHTTPRequest(authenticationURL, True)

        adobe_response_xml2 = etree.fromstring(response2, parser=safe_xml_parser())
        authCertBB, authCertAdobe = find_vendor_values(adobe_response_xml2, "certificate")


    if authCertBB is not None:
        authcertbb = etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authenticationCertificate"))
        authcertbb.set("ofByteBooks", "true")
        authcertbb.text = authCertBB

    if authCertAdobe is not None:
        authcertadobe = etree.SubElement(activationServiceInfo, etree.QName(NSMAP["adept"], "authenticationCertificate"))
        authcertadobe.set("ofByteBooks", "false")
        authcertadobe.text = authCertAdobe

    if authCertBB is None and authCertAdobe is None: 
        print("Warning: authCertBB and authCertAdobe are both None ...")

    
    write_file_atomically(get_activation_xml_path(), b"<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False))

    return True, "Done"

def encryptLoginCredentials(username, password, authenticationCertificate): 
    # type: (str, str, str) -> bytes

    from .libadobe import devkey_bytes as devkey_adobe
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

    username_bytes = bytearray(username.encode("utf-8"))
    password_bytes = bytearray(password.encode("utf-8"))

    ar.extend(bytearray(struct.pack("B", len(username_bytes))))
    ar.extend(username_bytes)
    ar.extend(bytearray(struct.pack("B", len(password_bytes))))
    ar.extend(password_bytes)

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


def buildSignInRequestForAnonAuthConvert(username, password, authenticationCertificate, use_bytebooks):
    # type: (str, str, str, bool) -> str

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
    signature = sign_node(root, use_bytebooks)
    if signature is None: 
        return None
    etree.SubElement(root, etree.QName(NSMAP["adept"], "signature")).text = signature

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")


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

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(root, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
    

def convertAnonAuthToAccount(username, passwd):

    # If you have an anonymous authorization, you can convert that to an AdobeID. 
    # Important: You can only do this ONCE for each AdobeID. 
    # The AdobeID you are using for this must not be connected to any ADE install.

    # TODO: This is untested for ByteBooks accounts.

    # This is intended for cases where people install ADE, use an anonymous auth, 
    # buy a couple books, and then decide to get a fresh AdobeID.

    from .libadobeFulfill import is_bytebooks_account

    # Get authenticationCertificate
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag) 

        # Link with the certificate and key of the registration's type, chosen the same way
        # as for fulfillments: ByteBooks if the activation has a complete set of ByteBooks
        # credentials, otherwise Adobe. Anonymous activations from older versions of the
        # plugin or from ADE only have Adobe credentials, without the ofByteBooks flag.
        use_bytebooks = is_bytebooks_account()
    except:
        return False, "Missing authenticationCertificate"

    authcert_bb, authcert_adobe = find_vendor_values(activationxml, "activationServiceInfo", "authenticationCertificate")
    authenticationCertificate = authcert_bb if use_bytebooks else authcert_adobe
    if authenticationCertificate is None:
        return False, "Missing authenticationCertificate"

    linkRequest = buildSignInRequestForAnonAuthConvert(username, passwd, authenticationCertificate, use_bytebooks)

    if linkRequest is None: 
        return False, "Signing failed"

    signInURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text + "/AddSignInDirect"
    if use_bytebooks:
        signInURL += "?ofByteBooks=1"
    linkResponse = sendRequestDocu(linkRequest, signInURL, True)
    if linkResponse is None: 
        return False, "Error while calling AddSignInDirect"

    try: 
        credentialsXML = etree.fromstring(linkResponse, parser=safe_xml_parser())
        
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
    write_file_atomically(get_activation_xml_path(), b"<?xml version=\"1.0\"?>\n" + etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False))

    
    return True, "Account linking successful"


def html_to_str(string):
    try: 
        from urllib.parse import unquote_plus
    except: 
        from urllib import unquote_plus

    data = unquote_plus(string)
    if isinstance(data, bytes):
        data = data.decode('utf-8')

    return data
    

def signIn(account_type, username, passwd):


    # Get authenticationCertificate
    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # TODO: Can the ByteBooks certificate really be missing? I'd assume ByteBooks will always send their cert ...
    authcertificate_bb, authcertificate_adobe = find_vendor_values(activationxml, "activationServiceInfo", "authenticationCertificate")

    if authcertificate_bb is None and authcertificate_adobe is None: 
        return False, "Server response missing auth certificate."

    
    # Type = "AdobeID" or "anonymous". For "anonymous", username and passwd need to be the empty string.
    signInRequest = buildSignInRequest(account_type, username, passwd, prefer_vendor(authcertificate_bb, authcertificate_adobe, True)[0])

    signInURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text + "/SignInDirect?ofByteBooks=1"

    credentials = sendRequestDocu(signInRequest, signInURL, True)
    
    
    #print("======================================================")
    #print("Sending request to " + signInURL)
    #print("Payload:")
    #print(signInRequest)
    #print("got response:")
    #print(credentials)
    #print("======================================================")


    try: 
        credentialsXML = etree.fromstring(credentials, parser=safe_xml_parser())
        
        if (credentialsXML.tag == adNS("error")): 
            err = credentialsXML.get("data")

            error_data = err.split(' ')

            if (error_data[0] == "E_AUTH_FAILED" and "CUS05051" in err): 
                # This only seems to occur on the old Adobe servers?
                return False, "Invalid username or password!"
            elif (error_data[0] == "E_AUTH_FAILED" and len(error_data) == 4 and error_data[3] != ""):
                return False, "The server refused our login: \n" + html_to_str(error_data[3])
            elif (error_data[0] == "E_AUTH_FAILED"):
                return False, "The server refused our login: \n" + err
            elif (error_data[0] == "E_ADEPT_RESET_PW_REQUIRED"):
                return False, "Server requires a password reset due to ByteBooks migration. \nSee https://dtsbytebooks.com/transition-help"
            else: 
                return False, "Unknown Adobe error:" + str(err)
            
        elif (credentialsXML.tag == adNS("credentials")):
            pass
            #print("Login successful")
        else: 
            return False, "Invalid main tag " + credentialsXML.tag
    
    except: 
        return False, "Invalid or empty response to login request (please open a bug report)"

    # Got correct credentials

    # The callers only handle a False return value, so check that the reply has everything
    # that's used below, instead of raising an exception halfway through.
    user_uuid = credentialsXML.findtext("./%s" % (adNS("user")))
    private_key_data_encrypted = credentialsXML.findtext("./%s" % (adNS("encryptedPrivateLicenseKey")))
    username_node = credentialsXML.find("./%s" % (adNS("username")))

    missing = []
    if not user_uuid:
        missing.append("user")
    if not private_key_data_encrypted:
        missing.append("encryptedPrivateLicenseKey")
    if account_type != "anonymous" and (username_node is None or not username_node.text):
        missing.append("username")
    if missing:
        return False, "Incomplete response to login request, missing %s (please open a bug report)" % (", ".join(missing))

    try:
        private_key_data = decrypt_with_device_key(base64.b64decode(private_key_data_encrypted))
    except (TypeError, ValueError):
        # Not base64 (that's a TypeError on Python 2), or not encrypted with the device key
        return False, "Could not decrypt the private license key in the login response (please open a bug report)"



    pkcs12_bb, pkcs12_adobe = find_vendor_values(credentialsXML, "pkcs12")

    if pkcs12_bb is None and pkcs12_adobe is None: 
        return False, "No pkcs12 in response"



    # Okay, now we got the credential response correct. Now "just" apply all these to the main activation.xml

    # The file is assembled as text and written as UTF-8 bytes at the end, so non-ASCII
    # usernames don't depend on the system's default encoding.
    content = "<?xml version=\"1.0\"?>\n"
    content += etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8").replace("</activationInfo>", "")

    # Yeah, that's ugly, but I didn't get etree to work with the different Namespaces ...

    content += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    content += "<adept:user>%s</adept:user>\n" % (user_uuid)

    username = ""
    if account_type != "anonymous": 
        username = username_node.text
        # TODO: Should we always write this? Windows does, MacOS doesn't.
        content += "<adept:username method=\"%s\">%s</adept:username>\n" % (username_node.get("method", account_type), xml_escape(username))

    if pkcs12_bb is not None:
        content += "<adept:pkcs12 ofByteBooks=\"true\">%s</adept:pkcs12>\n" % (pkcs12_bb)

    if pkcs12_adobe is not None: 
        content += "<adept:pkcs12 ofByteBooks=\"false\">%s</adept:pkcs12>\n" % (pkcs12_adobe)

    license_cert_bb, license_cert_adobe = find_vendor_values(credentialsXML, "licenseCertificate")

    if license_cert_bb is not None:
        content += "<adept:licenseCertificate ofByteBooks=\"true\">%s</adept:licenseCertificate>\n" % (license_cert_bb)

    if license_cert_adobe is not None: 
        content += "<adept:licenseCertificate ofByteBooks=\"false\">%s</adept:licenseCertificate>\n" % (license_cert_adobe)

    content += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>\n" % (base64.b64encode(private_key_data).decode("latin-1"))
    if authcertificate_bb is not None:
        content += "<adept:authenticationCertificate ofByteBooks=\"true\">%s</adept:authenticationCertificate>\n" % (authcertificate_bb)
    if authcertificate_adobe is not None: 
        content += "<adept:authenticationCertificate ofByteBooks=\"false\">%s</adept:authenticationCertificate>\n" % (authcertificate_adobe)
    content += "</adept:credentials>\n"
    content += "</activationInfo>\n"

    write_file_atomically(get_activation_xml_path(), content.encode("utf-8"))

    return True, "Done"

def exportProxyAuth(act_xml_path, activationToken):
    # This authorizes a tethered device. 
    # TODO: This is not yet properly adapted and tested for ByteBooks
    # ret, data = exportProxyAuth(act_xml_path, data)

    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # At some point I should probably rewrite this, but I want to be sure the format is
    # correct so I'm recreating the whole XML myself.

    rt_si_authURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("authURL"))).text
    rt_si_userInfoURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("userInfoURL"))).text
    rt_si_activationURL = activationxml.find("./%s/%s" % (adNS("activationServiceInfo"), adNS("activationURL"))).text
    rt_si_certificate_bb, rt_si_certificate_ad = find_vendor_values(activationxml, "activationServiceInfo", "certificate")


    rt_c_user = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    rt_c_privateLicenseKey = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("privateLicenseKey"))).text


    license_cert_bb, license_cert_adobe = find_vendor_values(activationxml, "credentials", "licenseCertificate")
    auth_cert_bb, auth_cert_adobe = find_vendor_values(activationxml, "credentials", "authenticationCertificate")




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
    ret += "<adept:authURL>%s</adept:authURL>" % (xml_escape(rt_si_authURL))
    ret += "<adept:userInfoURL>%s</adept:userInfoURL>" % (xml_escape(rt_si_userInfoURL))
    ret += "<adept:activationURL>%s</adept:activationURL>" % (xml_escape(rt_si_activationURL))
    if rt_si_certificate_ad is not None:
        ret += "<adept:certificate>%s</adept:certificate>" % (rt_si_certificate_ad)
    if rt_si_certificate_bb is not None:
        ret += "<adept:certificate ofByteBooks='true'>%s</adept:certificate>" % (rt_si_certificate_bb)
    ret += "</adept:activationServiceInfo>"

    ret += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">"
    ret += "<adept:user>%s</adept:user>" % (rt_c_user)
    if license_cert_adobe is not None:
        ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>" % (license_cert_adobe)
    if license_cert_bb is not None:
        ret += "<adept:licenseCertificate ofByteBooks='true'>%s</adept:licenseCertificate>" % (license_cert_bb)
    ret += "<adept:privateLicenseKey>%s</adept:privateLicenseKey>" % (rt_c_privateLicenseKey)

    if auth_cert_adobe is not None:
        ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>" % (auth_cert_adobe)
    if auth_cert_bb is not None:
        ret += "<adept:authenticationCertificate ofByteBooks='true'>%s</adept:authenticationCertificate>" % (auth_cert_bb)


    if rt_c_username is not None: 
        ret += "<adept:username method=\"%s\">%s</adept:username>" % (rt_c_usernameMethod, xml_escape(rt_c_username))

    ret += "</adept:credentials>"

    activationToken = activationToken.decode("utf-8")
    # Yeah, terrible hack, but Adobe sends the token with namespace but exports it without.
    activationToken = activationToken.replace(' xmlns="http://ns.adobe.com/adept"', '')

    ret += activationToken

    ret += "</activationInfo>"

    # Okay, now we can finally write this to the device. 

    try: 
        write_file_atomically(act_xml_path, ret.encode("utf-8"))
    except: 
        return False, "Can't write file"

    return True, "Done"
    

def buildActivateReqProxy(useVersionIndex = 0, proxyData = None):

    if proxyData is None: 
        return False, "Missing ProxyData"

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Build ID"

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False, "Invalid Build ID"

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        return False, "This version can't authorize"

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
    ret += "<adept:productName>%s</adept:productName>" % ("ByteBooks Digitial Editions")
    # YES, this typo ("Digitial" instead of "Digital") IS present in ADE and BDE.

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
    ret += "<adept:productName>%s</adept:productName>" % ("ByteBooks Digitial Editions")
    # Yes, the typo in "Digitial" is intended.
    ret += "<adept:fingerprint>%s</adept:fingerprint>" % (proxyData.find("./%s" % (adNS("fingerprint"))).text)


    ret += "</adept:targetDevice>"

    ret += addNonce()

    ret += "<adept:user>%s</adept:user>" % (local_activation_xml.find("./%s/%s" % (adNS("activationToken"), adNS("user"))).text)

    ret += "</adept:activate>"

    return True, ret


def buildActivateReq(useVersionIndex = 0): 

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid version index"

    try: 
        build_id = VAR_VER_BUILD_IDS[useVersionIndex]
    except:
        return False, "Invalid version index"

    if build_id not in VAR_VER_ALLOWED_BUILD_IDS_AUTHORIZE:
        return False, "Version not allowed"

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
    ret += "<adept:productName>%s</adept:productName>" % ("ByteBooks Digitial Editions")
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

def changeDeviceVersion(useVersionIndex = 0, onlyIfUnknown = False):
    # Makes device.xml report the given emulated version.

    if useVersionIndex >= len(VAR_VER_SUPP_CONFIG_NAMES):
        return False, "Invalid Version index"

    try:
        new_values = {
            "hobbes": VAR_VER_HOBBES_VERSIONS[useVersionIndex],
            "clientOS": VAR_VER_OS_IDENTIFIERS[useVersionIndex],
        }
        devicexml = etree.parse(get_device_path())
    except: 
        return False, "Error preparing version change"

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)


    if onlyIfUnknown:
        hobbes_version = None
        for f in devicexml.findall("./%s" % (adNS("version"))):
            if f.get("name") == "hobbes":
                hobbes_version = f.get("value")
    
        if hobbes_version in VAR_VER_HOBBES_VERSIONS:
            return True, ""


    changed = False
    for f in devicexml.findall("./%s" % (adNS("version"))):
        new_value = new_values.get(f.get("name"))
        if new_value is not None and f.get("value") != new_value:
            f.set("value", new_value)
            changed = True

    if not changed:
        return True, ""

    try: 
        write_file_atomically(get_device_path(), b"<?xml version=\"1.0\"?>\n" + etree.tostring(devicexml, encoding="utf-8", pretty_print=True, xml_declaration=False))
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
        return False, "Authorization not supported for this build ID"

    verbose_logging = False
    try: 
        from . import prefs
        acsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = acsmprefs["detailed_logging"]
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

    req_xml = etree.fromstring(activate_req, parser=safe_xml_parser())

    signature = sign_node(req_xml, True) 
    if signature is None: 
        print("Signing failed, missing pkcs12?")
        return False, "Signing failed"

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    if verbose_logging:
        print ("Activation request:")
        print(etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))

    data = "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

    ret = sendRequestDocu(data, VAR_ACS_SERVER_HTTPS + "/Activate?ofByteBooks=1", True)

    try: 
        credentialsXML = etree.fromstring(ret, parser=safe_xml_parser())
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
        print("Response from server (for Activate): ")
        print(ret)

    if proxyData is not None: 
        # If we have a proxy device, this function doesn't know where to store the activation.
        # Just return the data and have the caller figure that out.
        return True, etree.tostring(credentialsXML, encoding="utf-8", xml_declaration=False)

    # Append the parsed activationToken element to activation.xml.
    activationxml = etree.parse(get_activation_xml_path())
    activationxml.getroot().append(credentialsXML)

    write_file_atomically(get_activation_xml_path(), b"<?xml version=\"1.0\"?>\n" + etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False))

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
    # NOTE: This function seems unused, but should remain. It might be used by other plugins
    # exporting the private key.
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        privatekey = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("privateLicenseKey"))).text
        privatekey = base64.b64decode(privatekey)
        privatekey = privatekey[26:]
        return privatekey
    except: 
        return None