'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

from lxml import etree
import base64

#@@CALIBRE_COMPAT_CODE@@

from libadobe import addNonce, sign_node, get_cert_from_pkcs12, sendRequestDocu, sendRequestDocuRC, sendHTTPRequest
from libadobe import get_devkey_path, get_device_path, get_activation_xml_path
from libadobe import VAR_VER_SUPP_VERSIONS, VAR_VER_HOBBES_VERSIONS


 
def buildFulfillRequest(acsm):

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    

    activationxml = etree.parse(get_activation_xml_path())
    devicexml = etree.parse(get_device_path())


    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    device_uuid = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text
    try: 
        fingerprint = None
        device_type = None
        fingerprint = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("fingerprint"))).text
        device_type = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("deviceType"))).text
    except:
        pass

    if (fingerprint is None or fingerprint == "" or device_type is None or device_type == ""):
        # This should usually never happen with a proper activation, but just in case it does,
        # I'll leave this code in - it loads the fingerprint from the device data instead.
        fingerprint = devicexml.find("./%s" % (adNS("fingerprint"))).text
        device_type = devicexml.find("./%s" % (adNS("deviceType"))).text



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

    # Find matching client version depending on the Hobbes version. 
    # This way we don't need to store and re-load it for each fulfillment. 

    try: 
        v_idx = VAR_VER_HOBBES_VERSIONS.index(version)
        clientVersion = VAR_VER_SUPP_VERSIONS[v_idx]

    except:
        clientVersion = VAR_VER_SUPP_VERSIONS[0]



    request = ""
    request += "<?xml version=\"1.0\"?>"
    request += "<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">"
    request += "<adept:user>%s</adept:user>" % (user_uuid)
    request += "<adept:device>%s</adept:device>" % (device_uuid)
    request += "<adept:deviceType>%s</adept:deviceType>" % (device_type)
    request += etree.tostring(acsm, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
    request += "<adept:targetDevice>"

    request += "<adept:softwareVersion>%s</adept:softwareVersion>" % (version)
    request += "<adept:clientOS>%s</adept:clientOS>" % (clientOS)
    request += "<adept:clientLocale>%s</adept:clientLocale>" % (clientLocale)
    request += "<adept:clientVersion>%s</adept:clientVersion>" % (clientVersion)
    request += "<adept:deviceType>%s</adept:deviceType>" % (device_type)
    request += "<adept:productName>%s</adept:productName>" % ("ByteBooks Digitial Editions")
    # YES, this typo ("Digitial" instead of "Digital") IS present in BDE, just like it was in ADE.
    request += "<adept:fingerprint>%s</adept:fingerprint>" % (fingerprint)

    request += "<adept:activationToken>"
    request += "<adept:user>%s</adept:user>" % (user_uuid)
    request += "<adept:device>%s</adept:device>" % (device_uuid)
    request += "</adept:activationToken>"
    request += "</adept:targetDevice>"
    request += "</adept:fulfill>"
    return request

    



def buildInitLicenseServiceRequest(authURL, force_adobe):
    # type: (str, bool) -> str


    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())
    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

    ret = ""
    ret += "<?xml version=\"1.0\"?>"
    ret += "<adept:licenseServiceRequest xmlns:adept=\"http://ns.adobe.com/adept\" identity=\"user\">"
    ret += "<adept:operatorURL>%s</adept:operatorURL>" % (authURL)
    ret += addNonce()
    ret += "<adept:user>%s</adept:user>" % (user_uuid)
    ret += "</adept:licenseServiceRequest>"

    req_xml = etree.fromstring(ret)

    signature = sign_node(req_xml, not force_adobe)
    if (signature is None):
        return None

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")


def getDecryptedCert(pkcs12_b64_string = None, force_bytebooks = False): 
    
    if pkcs12_b64_string is None: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

        try: 
            certificate_bb = activationxml.find("./%s/%s[@ofByteBooks='true']" % (adNS("credentials"), adNS("pkcs12"))).text
        except AttributeError:
            # When old activation.xmls are loaded in the new plugin.
            certificate_bb = None

        try: 
            certificate_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("pkcs12")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )
        except:
            certificate_adobe = None

        if certificate_bb is None and certificate_adobe is None: 
            return None
        elif certificate_adobe is None: 
            pkcs12_b64_string = certificate_bb
        elif certificate_bb is None:
            pkcs12_b64_string = certificate_adobe
        elif force_bytebooks and certificate_bb is not None:
            pkcs12_b64_string = certificate_bb
        else: 
            pkcs12_b64_string = certificate_adobe

    pkcs12_data = base64.b64decode(pkcs12_b64_string)

    from libadobe import devkey_bytes as devkey_adobe
    
    if devkey_adobe is not None: 
        devkey_bytes = devkey_adobe
    else: 
        f = open(get_devkey_path(), "rb")
        devkey_bytes = f.read()
        f.close()

    try:     
        return get_cert_from_pkcs12(pkcs12_data, base64.b64encode(devkey_bytes))
    except: 
        return None

def buildAuthRequest(use_bytebooks = False):

    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)     

    my_cert = getDecryptedCert(None, use_bytebooks)
    if my_cert is None: 
        print("Can't decrypt pkcs12 with devkey!")
        return None


    ret = "<?xml version=\"1.0\"?>\n"
    ret += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    ret += "<adept:user>%s</adept:user>\n" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)
    ret += "<adept:certificate>%s</adept:certificate>\n" % (base64.b64encode(my_cert).decode("utf-8"))

    try: 
        license_cert_bb = activationxml.find("./%s/%s[@ofByteBooks='true']" % (adNS("credentials"), adNS("licenseCertificate"))).text
        auth_cert_bb = activationxml.find("./%s/%s[@ofByteBooks='true']" % (adNS("credentials"), adNS("authenticationCertificate"))).text
    except AttributeError:
        # When old activation.xmls are loaded by the new plugin.
        license_cert_bb = None
        auth_cert_bb = None


    try: 
        license_cert_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("licenseCertificate")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )

        auth_cert_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("authenticationCertificate")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )
    except: 
        license_cert_adobe = None
        auth_cert_adobe = None



    if use_bytebooks and license_cert_bb is not None and auth_cert_bb is not None:
        ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (license_cert_bb)
        ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (auth_cert_bb)

    elif auth_cert_adobe is None or license_cert_adobe is None: 
        print("Adobe cert is not available.")
        return None
    else: 
        ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (license_cert_adobe)
        ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (auth_cert_adobe)

    ret += "</adept:credentials>"


    return ret


def getAvailableCertTypes():
    # type: () -> tuple
    # Returns (has_bytebooks, has_adobe): whether the activation contains a complete set of
    # credentials (pkcs12, licenseCertificate and authenticationCertificate) of each type.
    # Entries without an ofByteBooks attribute (older activations) count as Adobe,
    # same as everywhere else in the plugin.

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    activationxml = etree.parse(get_activation_xml_path())

    def has_complete_set(bytebooks):
        for tag in ["pkcs12", "licenseCertificate", "authenticationCertificate"]:
            found = False
            for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS(tag))):
                flag = c.get("ofByteBooks")
                if bytebooks:
                    matches = (flag == "true")
                else:
                    matches = (flag is None or flag == "false")
                if matches and c.text:
                    found = True
                    break
            if not found:
                return False
        return True

    return has_complete_set(True), has_complete_set(False)

def is_bytebooks_account():
    return getAvailableCertTypes()[0]

def doOperatorAuth(operatorURL, force_adobe = False):
    # type: (str, bool) -> tuple
    # Returns (error, use_adobe): error is None on success, and use_adobe then 
    # says which certificate the operator accepted.

    has_bytebooks, has_adobe = getAvailableCertTypes()

    if not has_bytebooks and not has_adobe:
        return "The activation doesn't contain a complete set of certificates", None

    # Use the ByteBooks certificate if we have one, otherwise go straight to Adobe.
    use_adobe = force_adobe or not has_bytebooks

    if use_adobe and not has_adobe:
        return "The activation doesn't contain Adobe certificates", None

    auth_req = buildAuthRequest(not use_adobe)
    if auth_req is None:
        return "Failed to create auth request - buildAuthRequest returned None", None


    authURL = operatorURL
    # I don't think this is needed since callers shouldn't have this flag in their URLs.
    # authURL = authURL.replace('?ofByteBooks=1', '')
    if authURL.endswith("/Fulfill"):
        authURL = authURL[:-8]
    
    
    # The operator is the distributor's own ACS server, not ByteBooks. Don't validate TLS here,
    # same as for /Fulfill: lots of distributors have invalid or expired certs.
    
    try: 
        if not use_adobe:
            replyData = sendRequestDocu(auth_req, authURL + "/Auth?ofByteBooks=1", False).decode("utf-8")
        else:
            replyData = sendRequestDocu(auth_req, authURL + "/Auth", False).decode("utf-8")
    except: 
        return "ERROR: /Auth returned invalid data or no data at all.", None

    if not "<success" in replyData:
        if "<error" in replyData and 'E_ADEPT_INVALID_CERTIFICATE' in replyData and not use_adobe and has_adobe:
            print("Operator auth using ByteBooks certificate failed, this might be an older ACS server. Retrying with Adobe certificates.")
            return doOperatorAuth(operatorURL, True)
        return "ERROR: Operator responded with %s\n" % replyData, None

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())

    activationURL = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("activationURL"))).text

    init_license_service_request = buildInitLicenseServiceRequest(authURL, use_adobe)

    if (init_license_service_request is None):
        return "Creating license request failed!", None


    try:
        if use_adobe:
            resp = sendRequestDocu(init_license_service_request, activationURL + "/InitLicenseService", True).decode("utf-8")
        else:
            resp = sendRequestDocu(init_license_service_request, activationURL + "/InitLicenseService?ofByteBooks=1", True).decode("utf-8")
    except: 
        return "ERROR: /InitLicenseService returned invalid data or no data at all.", None

    if "<error" in resp:
        return "Looks like that failed: %s" % resp, None
    elif "<success" in resp:
        return None, use_adobe
    else: 
        return "Useless response: %s" % resp, None



def operatorAuth(operatorURL):

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())
    try: 
        operator_url_list = activationxml.findall("./%s/%s" % (adNS("operatorURLList"), adNS("operatorURL")))

        for member in operator_url_list:
            if member.text.strip() == operatorURL:
                #print("Already authenticated to operator")
                # We don't know which certificate it accepted; fulfill() finds out.
                return None, None
    except:
        pass

    
    ret, reqtype = doOperatorAuth(operatorURL)
    if (ret is not None):
        return ("doOperatorAuth error: %s" % ret), None

    #reqtype is now a boolean. If true, Adobe, if false, ByteBooks.

    # Check if list exists:
    list = activationxml.find("./%s" % (adNS("operatorURLList")))
    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

    if list is None: 
        x = etree.SubElement(activationxml.getroot(), etree.QName(NSMAP["adept"], "operatorURLList"), nsmap=NSMAP)
        etree.SubElement(x, etree.QName(NSMAP["adept"], "user")).text = user_uuid
        list = activationxml.find("./%s" % (adNS("operatorURLList")))
        if list is None: 
            return "Err, this list should not be none right now ...", None
    
    etree.SubElement(list, etree.QName(NSMAP["adept"], "operatorURL")).text = operatorURL

    f = open(get_activation_xml_path(), "wb")
    f.write(b"<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False))
    f.close()

    return None, reqtype



def buildRights(license_token_node):
    ret = "<?xml version=\"1.0\"?>\n"
    ret += "<adept:rights xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    
    # Add license token
    ret += etree.tostring(license_token_node, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

    ret += "<adept:licenseServiceInfo>\n"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    lic_token_url = license_token_node.find("./%s" % (adNS("licenseURL"))).text

    ret += "<adept:licenseURL>%s</adept:licenseURL>\n" % lic_token_url

    # Get cert for this license URL:
    activationxml = etree.parse(get_activation_xml_path())

    try: 
        licInfo = activationxml.findall("./%s/%s" % (adNS("licenseServices"), adNS("licenseServiceInfo")))
        
        found = False

        for member in licInfo:
            if member.find("./%s" % (adNS("licenseURL"))).text == lic_token_url:
                ret += "<adept:certificate>%s</adept:certificate>\n" % (member.find("./%s" % (adNS("certificate"))).text)
                found = True
                break
    except: 
        pass

    if not found:
        print("Did not find the licenseService certificate in the activation data.")
        print("This usually means it failed to download from the distributor's servers.")
        print("Please try to download an ACSM book from the ByteBooks Sample Library,")
        print("then if that was successful, try your ACSM book file again.")
        return None

    ret += "</adept:licenseServiceInfo>\n"
    ret += "</adept:rights>\n"

    return ret


def signAndSendFulfillRequest(fulfill_request, use_adobe, fulfillURL):
    # type: (str, bool, str) -> str
    # Signs the fulfill request with the Adobe key (use_adobe) or the ByteBooks
    # key, sends it and returns the reply. Returns None if signing failed.

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    fulfill_request_xml = etree.fromstring(fulfill_request)
    signature = sign_node(fulfill_request_xml, not use_adobe)
    if (signature is None):
        return None

    if not use_adobe:
        fulfillURL = fulfillURL + "?ofByteBooks=1"

    etree.SubElement(fulfill_request_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    fulfill_req_signed = "<?xml version=\"1.0\"?>\n" + etree.tostring(fulfill_request_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

    #print("will send:\n %s" % fulfill_req_signed)
    #print("Sending fulfill request to %s" % fulfillURL)

    # For debugging only
    # fulfillURL = fulfillURL.replace("https:", "http:")

    try: 
        ret = sendRequestDocu(fulfill_req_signed, fulfillURL, False).decode("utf-8")
        return ret
    except: 
        print("Fulfillment request failed ...")
        return None


def fulfill(acsm_file, do_notify = False):

    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        acsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = acsmprefs["detailed_logging"]
    except:
        pass

    
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    acsmxml = None
    
    try: 
        acsmxml = etree.parse(acsm_file)
    except: 
        return False, "ACSM not found or invalid"

    #print(etree.tostring(acsmxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    dcNS = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

    try: 
        mimetype = acsmxml.find("./%s/%s/%s" % (adNS("resourceItemInfo"), adNS("metadata"), dcNS("format"))).text

        if (mimetype == "application/pdf"):
            #print("You're trying to fulfill a PDF file.")
            pass
        elif (mimetype == "application/epub+zip"):
            #print("Trying to fulfill an EPUB file ...")
            pass
        else: 
            print("Weird mimetype: %s" % (mimetype))
            print("Continuing anyways ...")
        
    except: 
        # Some books, like from Google Play books, use a different format and don't have that metadata tag.
        pass


    # Get operator URL: 
    operatorURL = None
    try: 
        operatorURL = acsmxml.find("./%s" % (adNS("operatorURL"))).text.strip()
    except: 
        pass

    if (operatorURL is None or len(operatorURL) == 0):
        return False, "OperatorURL missing in ACSM"

    fulfillURL = operatorURL + "/Fulfill"

    ret, use_adobe = operatorAuth(fulfillURL)
    if (ret is not None):
        return False, "operatorAuth error: %s" % ret


    fulfill_request = buildFulfillRequest(acsmxml)

    if verbose_logging:
        print("Fulfill request:")
        print(fulfill_request)

    # If operatorAuth() just authenticated us, it knows which certificate the
    # operator accepted. If we were already authenticated (earlier, or by ADE/BDE
    # before an import), it returns None: then use ByteBooks if we have it, and
    # only fall back to Adobe if the operator rejects that AND we have Adobe
    # certificates.

    can_retry_with_adobe = False
    if use_adobe is None:
        has_bytebooks, has_adobe = getAvailableCertTypes()
        use_adobe = not has_bytebooks
        can_retry_with_adobe = has_bytebooks and has_adobe


    replyData = signAndSendFulfillRequest(fulfill_request, use_adobe, fulfillURL)
    if (replyData is None):
        return False, "Signing failed!"

    if "<error" in replyData and "E_ADEPT_INVALID_CERTIFICATE" in replyData and can_retry_with_adobe:
        print("Operator rejected the request signed with the ByteBooks certificate, this might be an older ACS server. Retrying with Adobe certificates.")
        use_adobe = True
        replyData = signAndSendFulfillRequest(fulfill_request, use_adobe, fulfillURL)
        if (replyData is None):
            return False, "Signing failed!"

    if "<error" in replyData:
        if "E_ADEPT_DISTRIBUTOR_AUTH" in replyData:
            # This distributor *always* wants authentication, so force that again.
            # The auth tells us which certificate the operator accepted, so re-sign to match.
            ret, use_adobe = doOperatorAuth(fulfillURL)

            if (ret is not None):
                return False, "doOperatorAuth error: %s" % ret

            replyData = signAndSendFulfillRequest(fulfill_request, use_adobe, fulfillURL)
            if (replyData is None):
                return False, "Signing failed!"
            if "<error" in replyData:
                return False, "Looks like there's been an error during Fulfillment even after auth: %s" % replyData
        else: 
            return False, "Looks like there's been an error during Fulfillment: %s" % replyData

    if verbose_logging:
        print("fulfillmentResult:")
        print(replyData)

    adobe_fulfill_response = etree.fromstring(replyData)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    licenseURL = adobe_fulfill_response.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("licenseURL"))).text


    notify_success = False
    if do_notify:
        print("Notifying server ...")
        success, response = performFulfillmentNotification(adobe_fulfill_response, not use_adobe)
        if not success: 
            print("Some errors occurred during notify: ")
            print(response)
            print("The book was probably still downloaded correctly.")
        else: 
            notify_success = True
    else:
        print("Not notifying any server since that was disabled.")



    is_returnable = False
    try: 
        is_returnable_tx = adobe_fulfill_response.find("./%s/%s" % (adNS("fulfillmentResult"), adNS("returnable"))).text
        if is_returnable_tx.lower() == "true":
            is_returnable = True
    except: 
        pass

    if (is_returnable and notify_success):
        # Only support loan returning if we also notified ACS. 
        # Otherwise the server gets confused and we don't want that.
        try: 
            updateLoanReturnData(adobe_fulfill_response, False, use_adobe)
        except: 
            print("Warning: Could not add loan return data to loan record. You may not be able to return this book.")

    success, response = fetchLicenseServiceCertificate(licenseURL, operatorURL, use_adobe)

    if success is False: 
        print("Why did the license download fail?")
        print("This is probably a temporary error on the distributor's server")
        return False, response

    return True, replyData



def updateLoanReturnData(fulfillmentResultToken, forceTestBehaviour=False, use_adobe=False):

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    dcNS = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

    try: 
        fulfillment_id = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("fulfillment"))).text
        if (fulfillment_id is None):
            print("Fulfillment ID not found, can't generate loan token")
            return False

    except: 
        print("Loan token error")
        return False

    try: 
        operatorURL = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("operatorURL"))).text
    except: 
        print("OperatorURL missing")
        return False
    

    book_name = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata"), dcNS("title"))).text 

    userUUID = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("user"))).text
    try: 
        deviceUUID = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("device"))).text
    except: 
        activationxml = etree.parse(get_activation_xml_path())
        deviceUUID = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text


    permissions = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("permissions")))

    display = permissions.findall("./%s" % (adNS("display")))[0]

    try: 
        dsp_until = display.find("./%s" % (adNS("until"))).text
    except: 
        print("error with DSP")
        return False

    if (dsp_until is None):
        print("No validUntil thing")
        return False

    
    # "userUUID" is the user UUID
    # "deviceUUID" is the device UUID
    # "loanID" is the loan ID
    # "validUntil" is how long it's valid

    new_loan_record = {
            "book_name": book_name,
            "user": userUUID,
            "device": deviceUUID,
            "loanID": fulfillment_id,
            "operatorURL": operatorURL,
            "validUntil": dsp_until, 
            "useByteBooks": not use_adobe
        }

    if forceTestBehaviour:
        return new_loan_record

    addLoanRecordToConfigFile(new_loan_record)

    return True

    


def addLoanRecordToConfigFile(new_loan_record):

    try: 
        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        acsmprefs = prefs.ACSMInput_Prefs()
    except: 
        print("Exception while reading config file")
        return False

    # Add all necessary information for a book return to the JSON array, replacing
    # an older record of the same loan if there is one.
    # The config widget can then read this and present a list of not-yet-returned
    # books, and can then return them.
    # Also, the config widget is responsible for cleaning up that list once a book's validity period is up.
    acsmprefs.add_loan(new_loan_record)

    return True


def tryReturnBook(bookData): 


    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        acsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = acsmprefs["detailed_logging"]
    except:
        pass


    try: 
        user = bookData["user"]
        loanID = bookData["loanID"]
        device = bookData["device"]
        operatorURL = bookData["operatorURL"]
    except: 
        print("Invalid book data!")
        return False, "Invalid book data"

    try: 
        use_bytebooks = bookData["useByteBooks"]
    except: 
        use_bytebooks = False


    req_data = "<?xml version=\"1.0\"?>"
    req_data += "<adept:loanReturn xmlns:adept=\"http://ns.adobe.com/adept\">"
    req_data += "<adept:user>%s</adept:user>" % (user)
    if device is not None: 
        req_data += "<adept:device>%s</adept:device>" % (device)
    req_data += "<adept:loan>%s</adept:loan>" % (loanID)
    req_data += addNonce()
    req_data += "</adept:loanReturn>"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    full_text_xml = etree.fromstring(req_data)

    signature = sign_node(full_text_xml, use_bytebooks)
    if (signature is None):
        print("SIGN ERROR!")
        return False, "Sign error"

    etree.SubElement(full_text_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    return_server = operatorURL + "/LoanReturn"
    if use_bytebooks:
        return_server += "?ofByteBooks=1"

    print("Notifying loan return server %s" % (return_server))
    doc_send = "<?xml version=\"1.0\"?>\n" + etree.tostring(full_text_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
    if verbose_logging:
        print(doc_send)


    try:
        retval = sendRequestDocu(doc_send, return_server, False).decode("utf-8")
    except: 
        print("Error while returning!")
        return False, "sendRequest failed."

    if "<error" in retval: 
        print("Loan return failed: %s" % (retval))
        return False, retval
    elif "<envelope" in retval: 
        print("Loan return successful")
        if verbose_logging:
            print(retval)
        bl, txt = performFulfillmentNotification(etree.fromstring(retval), use_bytebooks, user=user, device=device)
        if not bl: 
            print("Error while notifying of book return. Book's probably still been returned properly.")
        return True, retval
    else: 
        print("Invalid loan return response: %s" % (retval))
        return False, retval



def performFulfillmentNotification(fulfillmentResultToken, use_bytebooks, user = None, device = None):

    verbose_logging = False
    try: 
        import calibre_plugins.deacsm.prefs as prefs
        acsmprefs = prefs.ACSMInput_Prefs()
        verbose_logging = acsmprefs["detailed_logging"]
    except:
        pass

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    # Debug output for PassHash testing: 
    # print(etree.tostring(fulfillmentResultToken, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))

    try: 
        notifiers = fulfillmentResultToken.findall("./%s/%s" % (adNS("fulfillmentResult"), adNS("notify")))
    except:
        pass

    if len(notifiers) == 0: 
        try: 
            notifiers = fulfillmentResultToken.findall("./%s" % (adNS("notify")))
        except: 
            pass

    if len(notifiers) == 0: 
        try: 
            notifiers = fulfillmentResultToken.findall("./%s/%s" % (adNS("envelope"), adNS("notify")))
        except: 
            pass

    if len(notifiers) == 0:
        print("<notify> tag not found. Guess nobody wants to be notified.")
        #print(etree.tostring(fulfillmentResultToken, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))
        return True, ""
    

    errmsg = ""
    errmsg_crit = ""

    for element in notifiers:

        url = element.find("./%s" % (adNS("notifyURL"))).text
        body = element.find("./%s" % (adNS("body")))

        critical = True

        if element.get("critical", "yes") == "no":
            critical = False
            print("Notifying optional server %s" % (url))
        else: 
            print("Notifying server %s" % (url))
        

        if (user is None):
            try: 
                # "Normal" Adobe fulfillment
                user = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("user"))).text
            except AttributeError:
                # B&N Adobe PassHash fulfillment. Doesn't use notifications usually ...
                #user = body.find("./%s" % (adNS("user"))).text
                print("Skipping notify due to passHash?")
                print("If this is not a passHash book pls open a bug report.")
                continue
        
        if (device is None):
            try: 
                # "Normal" Adobe fulfillment
                device = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("device"))).text
            except:
                print("Missing deviceID for loan metadata ... why?")
                print("Reading from device.xml instead.")
                # Lets try to read this from the activation ...
                activationxml = etree.parse(get_activation_xml_path())
                device = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text



        
        full_text = "<adept:notification xmlns:adept=\"http://ns.adobe.com/adept\">"
        full_text += "<adept:user>%s</adept:user>" % user
        full_text += "<adept:device>%s</adept:device>" % device       
        full_text += etree.tostring(body, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        full_text += addNonce()
        full_text += "</adept:notification>"

            
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        etree.register_namespace("adept", NSMAP["adept"])

        full_text_xml = etree.fromstring(full_text)

        signature = sign_node(full_text_xml, use_bytebooks)
        if (signature is None):
            print("SIGN ERROR!")
            continue

        etree.SubElement(full_text_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

        doc_send = "<?xml version=\"1.0\"?>\n" + etree.tostring(full_text_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        
        # Debug: Print notify request
        if (verbose_logging):
            print("Notify payload XML:")
            print(doc_send)

        if use_bytebooks:
            if "?" in url: 
                url = url + "&ofByteBooks=1"
            else: 
                url = url + "?ofByteBooks=1"

        try: 
            code, msg = sendRequestDocuRC(doc_send, url)
        except:
            if not critical:
                print("There was an error during an optional fulfillment notification:")
                import traceback
                traceback.print_exc()
                print("Continuing execution ...")
                continue
            else:
                print("Error during critical notification:")
                raise

        try: 
            msg = msg.decode("utf-8")
        except:
            pass

        if verbose_logging:
            print("MSG:")
            print(msg)

        if "<error" in msg: 
            print("Fulfillment notification error: %s" % (msg))
            errmsg += "ERROR\n" + url + "\n" + msg + "\n\n"
            if critical:
                errmsg_crit += "ERROR\n" + url + "\n" + msg + "\n\n"

        elif "<success" in msg: 
            print("Fulfillment notification successful.")
        elif code == 204:
            print("Fulfillment notification successful (204).")
        else: 
            print("Weird Fulfillment Notification response: %s" % (msg))
            errmsg += "ERROR\n" + url + "\n" + msg + "\n\n"
            if critical:
                errmsg_crit += "ERROR\n" + url + "\n" + msg + "\n\n"


    if device is None and errmsg_crit != "":
        errmsg_crit = ""
        print("Skipping critical notification failure due to weird book.")
        

    if errmsg_crit == "": 
        return True, ""

    return False, errmsg


def quote_query_value(value):
    try: 
        from urllib.parse import quote
    except ImportError:
        from urllib import quote

    # Python 2's quote() raises KeyError on unicode with non-ASCII characters,
    # so always hand it UTF-8 bytes. Python 3's quote() accepts bytes as well.
    if not isinstance(value, bytes):
        value = value.encode("utf-8")
    return quote(value)

def fetchLicenseServiceCertificate(licenseURL, operatorURL, use_adobe = False):

    # Check if we already have a cert for this URL: 
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())

    try: 
        licInfo = activationxml.findall("./%s/%s" % (adNS("licenseServices"), adNS("licenseServiceInfo")))

        for member in licInfo:
            if member.find("./%s" % (adNS("licenseURL"))).text == licenseURL:
                return True, "Done"
    except:
        pass

    # Check if list exists:
    list = activationxml.find("./%s" % (adNS("licenseServices")))

    if list is None: 
        list = etree.SubElement(activationxml.getroot(), etree.QName(NSMAP["adept"], "licenseServices"), nsmap=NSMAP)
    
    info_entry = etree.SubElement(list, etree.QName(NSMAP["adept"], "licenseServiceInfo"))

    licenseServiceInfoReq = operatorURL + "/LicenseServiceInfo?licenseURL=" + quote_query_value(licenseURL) 
    if not use_adobe:
        licenseServiceInfoReq = licenseServiceInfoReq + "&ofByteBooks=1"

    try: 
        response = sendHTTPRequest(licenseServiceInfoReq, False).decode("utf-8")
    except: 
        return False, "HTTP download for the licenseServiceInfo failed ... why?"

    if "<error" in response: 
        return False, "Looks like that failed: %s" % response
    elif "<licenseServiceInfo" in response: 
        pass
    else: 
        return False, "Looks like that failed: %s" % response


    #print(response)

    responseXML = etree.fromstring(response)

    server_cert = responseXML.find("./%s" % (adNS("certificate"))).text
    server_lic_url = responseXML.find("./%s" % (adNS("licenseURL"))).text

    etree.SubElement(info_entry, etree.QName(NSMAP["adept"], "licenseURL")).text = server_lic_url
    etree.SubElement(info_entry, etree.QName(NSMAP["adept"], "certificate")).text = server_cert

    f = open(get_activation_xml_path(), "wb")
    f.write(b"<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False))
    f.close()

    return True, "Done"



