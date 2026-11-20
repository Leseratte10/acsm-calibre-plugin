'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

from lxml import etree
import base64
import random
import time

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
        # Version not present, probably the "old" 10.0.4 entry. 
        # As 10.X is in the 3.0 range, assume we're on ADE 3.0
        clientVersion = "3.0.1.91394"



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

    



def buildInitLicenseServiceRequest(authURL):
    # type: (str) -> str


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

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    req_xml = etree.fromstring(ret)

    signature = sign_node(req_xml, True)
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

        certificate_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("pkcs12")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )

        if force_bytebooks and certificate_bb is not None:
            pkcs12_b64_string = certificate_bb
        else: 
            pkcs12_b64_string = certificate_adobe

    pkcs12_data = base64.b64decode(pkcs12_b64_string)

    try: 
        from libadobe import devkey_bytes as devkey_adobe
    except: 
        pass

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


    license_cert_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("licenseCertificate")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )

    auth_cert_adobe = next(
                c.text for c in activationxml.findall("./%s/%s" % (adNS("credentials"), adNS("authenticationCertificate")))
                if "ofByteBooks" not in c.attrib or c.attrib['ofByteBooks'] == 'false'
            )



    if use_bytebooks and license_cert_bb is not None and auth_cert_bb is not None:
        ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (license_cert_bb)
        ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (auth_cert_bb)

    else: 
        ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (license_cert_adobe)
        ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (auth_cert_adobe)

    ret += "</adept:credentials>"


    return ret


def doOperatorAuth(operatorURL, force_adobe = False):
    # type: (str, bool) -> str

    auth_req = buildAuthRequest(not force_adobe)

    if auth_req is None:
        return "Failed to create auth request", None


    authURL = operatorURL
    authURL = authURL.replace('?ofByteBooks=1', '')
    if authURL.endswith("Fulfill"):
        authURL = authURL.replace("/Fulfill", "")
    
    
    if not force_adobe:
        replyData = sendRequestDocu(auth_req, authURL + "/Auth?ofByteBooks=1").decode("utf-8")
    else:
        replyData = sendRequestDocu(auth_req, authURL + "/Auth").decode("utf-8")

    if not "<success" in replyData:
        if "<error" in replyData and 'E_ADEPT_INVALID_CERTIFICATE' in replyData and not force_adobe:
            print("Operator auth using ByteBooks certificate failed, this might be an older ACS server. Retrying with Adobe certificates.")
            return doOperatorAuth(operatorURL, True)
        return "ERROR: Operator responded with %s\n" % replyData, None

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())

    activationURL = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("activationURL"))).text

    init_license_service_request = buildInitLicenseServiceRequest(authURL)

    if (init_license_service_request is None):
        return "Creating license request failed!", None


    resp = sendRequestDocu(init_license_service_request, activationURL + "/InitLicenseService?ofByteBooks=1").decode("utf-8")
    if "<error" in resp: 
        return "Looks like that failed: %s" % resp, None
    elif "<success" in resp: 
        return None, force_adobe
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
                return None, None
    except:
        pass

    
    ret = doOperatorAuth(operatorURL)
    if (ret is not None):
        return "doOperatorAuth error: %s" % ret, None

    #ret is now a boolean. If true, Adobe, if false, Bytebooks.

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

    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))
    f.close()

    return None, ret



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
        print("Please try to download an ACSM book from the Adobe Sample Library, then if that was successful, ")
        print("try your ACSM book file again.")
        return None

    ret += "</adept:licenseServiceInfo>\n"
    ret += "</adept:rights>\n"

    return ret


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

    fulfillURL = operatorURL + "/Fulfill?ofByteBooks=1"

    ret, use_adobe = operatorAuth(fulfillURL)
    if (ret is not None):
        return False, "operatorAuth error: %s" % ret


    fulfill_request = buildFulfillRequest(acsmxml)

    if verbose_logging:
        print("Fulfill request:")
        print(fulfill_request)

    fulfill_request_xml = etree.fromstring(fulfill_request)
    # Sign the request:
    signature = sign_node(fulfill_request_xml, not use_adobe)
    if (signature is None):
        return False, "Signing failed!"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    
    etree.SubElement(fulfill_request_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    fulfill_req_signed = "<?xml version=\"1.0\"?>\n" + etree.tostring(fulfill_request_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

    #print("will send:\n %s" % fulfill_req_signed)
    #print("Sending fulfill request to %s" % fulfillURL)

    # For debugging only
    # fulfillURL = fulfillURL.replace("https:", "http:")

    replyData = sendRequestDocu(fulfill_req_signed, fulfillURL).decode("utf-8")

    if "<error" in replyData: 
        if "E_ADEPT_DISTRIBUTOR_AUTH" in replyData:
            # This distributor *always* wants authentication, so force that again
            ret = doOperatorAuth(fulfillURL)

            if (ret is not None):
                return False, "doOperatorAuth error: %s" % ret

            replyData = sendRequestDocu(fulfill_req_signed, fulfillURL).decode("utf-8")
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


    if do_notify:
        print("Notifying server ...")
        success, response = performFulfillmentNotification(adobe_fulfill_response, not use_adobe)
        if not success: 
            print("Some errors occurred during notify: ")
            print(response)
            print("The book was probably still downloaded correctly.")
    else:
        print("Not notifying any server since that was disabled.")



    is_returnable = False
    try: 
        is_returnable_tx = adobe_fulfill_response.find("./%s/%s" % (adNS("fulfillmentResult"), adNS("returnable"))).text
        if is_returnable_tx.lower() == "true":
            is_returnable = True
    except: 
        pass

    if (is_returnable and do_notify):
        # Only support loan returning if we also notified ACS. 
        # Otherwise the server gets confused and we don't want that.
        updateLoanReturnData(adobe_fulfill_response, False, use_adobe)

    success, response = fetchLicenseServiceCertificate(licenseURL, operatorURL)

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
            "useBytebooks": not use_adobe
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
    
    acsmprefs.refresh()

    # Check if that exact loan is already in the list, and if so, delete it:
    done = False
    while not done:
        done = True
        for book in acsmprefs["list_of_rented_books"]:
            if book["loanID"] == new_loan_record["loanID"]:
                done = False
                acsmprefs["list_of_rented_books"].remove(book)
                break


    # Add all necessary information for a book return to the JSON array.
    # The config widget can then read this and present a list of not-yet-returned
    # books, and can then return them.
    # Also, the config widget is responsible for cleaning up that list once a book's validity period is up.
    acsmprefs["list_of_rented_books"].append(new_loan_record)
    acsmprefs.commit()

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
        use_bytebooks = bookData["useBytebooks"]
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


    retval = sendRequestDocu(doc_send, return_server).decode("utf-8")

    if "<error" in retval: 
        print("Loan return failed: %s" % (retval))
        return False, retval
    elif "<envelope" in retval: 
        print("Loan return successful")
        if verbose_logging:
            print(retval)
        bl, txt = performFulfillmentNotification(etree.fromstring(retval), use_bytebooks, True, user=user, device=device)
        if not bl: 
            print("Error while notifying of book return. Book's probably still been returned properly.")
        return True, retval
    else: 
        print("Invalid loan return response: %s" % (retval))
        return False, retval



def performFulfillmentNotification(fulfillmentResultToken, use_bytebooks, forceOptional = False, user = None, device = None):

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




def fetchLicenseServiceCertificate(licenseURL, operatorURL):

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
        x = etree.SubElement(activationxml.getroot(), etree.QName(NSMAP["adept"], "licenseServices"), nsmap=NSMAP)
        list = activationxml.find("./%s" % (adNS("licenseServices")))
        if list is None: 
            return False, "Err, this list should not be none right now ..."
    
    info_entry = etree.SubElement(list, etree.QName(NSMAP["adept"], "licenseServiceInfo"))

    licenseServiceInfoReq = operatorURL + "/LicenseServiceInfo?licenseURL=" + licenseURL + "&ofByteBooks=1"

    try: 
        response = sendHTTPRequest(licenseServiceInfoReq).decode("utf-8")
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

    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))
    f.close()

    return True, "Done"



