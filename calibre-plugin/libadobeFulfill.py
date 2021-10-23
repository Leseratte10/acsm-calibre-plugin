from lxml import etree
import base64

try: 
    from libadobe import addNonce, sign_node, get_cert_from_pkcs12, sendRequestDocu, sendRequestDocuRC, sendHTTPRequest
    from libadobe import get_devkey_path, get_device_path, get_activation_xml_path
except: 
    from calibre_plugins.deacsm.libadobe import addNonce, sign_node, get_cert_from_pkcs12, sendRequestDocu, sendRequestDocuRC, sendHTTPRequest
    from calibre_plugins.deacsm.libadobe import get_devkey_path, get_device_path, get_activation_xml_path

 
def buildFulfillRequest(acsm):

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    

    activationxml = etree.parse(get_activation_xml_path())
    devicexml = etree.parse(get_device_path())


    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text
    device_uuid = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("device"))).text
    device_type = devicexml.find("./%s" % (adNS("deviceType"))).text
    device_class = devicexml.find("./%s" % (adNS("deviceClass"))).text
    fingerprint = devicexml.find("./%s" % (adNS("fingerprint"))).text



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


    request = ""
    request += "<?xml version=\"1.0\"?>\n"
    request += "<adept:fulfill xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    request += "<adept:user>%s</adept:user>\n" % (user_uuid)
    request += "<adept:device>%s</adept:device>\n" % (device_uuid)
    request += "<adept:deviceType>%s</adept:deviceType>\n" % (device_type)
    request += etree.tostring(acsm, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
    request += "<adept:targetDevice>\n"

    request += "<adept:softwareVersion>%s</adept:softwareVersion>\n" % (version)
    request += "<adept:clientOS>%s</adept:clientOS>\n" % (clientOS)
    request += "<adept:clientLocale>%s</adept:clientLocale>\n" % (clientLocale)
    request += "<adept:clientVersion>%s</adept:clientVersion>\n" % (device_class)
    request += "<adept:deviceType>%s</adept:deviceType>\n" % (device_type)
    request += "<adept:fingerprint>%s</adept:fingerprint>\n" % (fingerprint)

    request += "<adept:activationToken>\n"
    request += "<adept:user>%s</adept:user>\n" % (user_uuid)
    request += "<adept:device>%s</adept:device>\n" % (device_uuid)
    request += "</adept:activationToken>\n"
    request += "</adept:targetDevice>\n"
    request += "</adept:fulfill>\n"

    return request



def buildInitLicenseServiceRequest(authURL: str):


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

    signature = sign_node(req_xml)
    if (signature is None):
        return None

    etree.SubElement(req_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    return "<?xml version=\"1.0\"?>\n" + etree.tostring(req_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")

def buildAuthRequest():

    activationxml = etree.parse(get_activation_xml_path())
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    user_pkcs12 = base64.b64decode(activationxml.find("./%s/%s" % (adNS("credentials"), adNS("pkcs12"))).text)


    f = open(get_devkey_path(), "rb")
    devkey_bytes = f.read()
    f.close()

    my_cert = get_cert_from_pkcs12(user_pkcs12, base64.b64encode(devkey_bytes))


    ret = "<?xml version=\"1.0\"?>\n"
    ret += "<adept:credentials xmlns:adept=\"http://ns.adobe.com/adept\">\n"
    ret += "<adept:user>%s</adept:user>\n" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text)
    ret += "<adept:certificate>%s</adept:certificate>\n" % (base64.b64encode(my_cert).decode("utf-8"))
    ret += "<adept:licenseCertificate>%s</adept:licenseCertificate>\n" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("licenseCertificate"))).text)
    ret += "<adept:authenticationCertificate>%s</adept:authenticationCertificate>\n" % (activationxml.find("./%s/%s" % (adNS("credentials"), adNS("authenticationCertificate"))).text)
    ret += "</adept:credentials>"


    return ret


def doOperatorAuth(operatorURL: str):
    auth_req = buildAuthRequest()

    authURL = operatorURL
    if authURL.endswith("Fulfill"):
        authURL = authURL.replace("/Fulfill", "")


    replyData = sendRequestDocu(auth_req, authURL + "/Auth").decode("utf-8")

    if not "<success" in replyData:
        return "ERROR: Operator responded with %s\n" % replyData

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())

    activationURL = activationxml.find("./%s/%s" % (adNS("activationToken"), adNS("activationURL"))).text

    init_license_service_request = buildInitLicenseServiceRequest(authURL)

    if (init_license_service_request is None):
        return "Creating license request failed!"


    resp = sendRequestDocu(init_license_service_request, activationURL + "/InitLicenseService").decode("utf-8")
    if "<error" in resp: 
        return "Looks like that failed: %s" % resp
    elif "<success" in resp: 
        return None
    else: 
        return "Useless response: %s" % resp



def operatorAuth(operatorURL: str):

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }    
    etree.register_namespace("adept", NSMAP["adept"])

    activationxml = etree.parse(get_activation_xml_path())
    try: 
        operator_url_list = activationxml.findall("./%s/%s" % (adNS("operatorURLList"), adNS("operatorURL")))

        for member in operator_url_list:
            if member.text.strip() == operatorURL:
                #print("Already authenticated to operator")
                return None
    except:
        pass

    
    ret = doOperatorAuth(operatorURL)
    if (ret is not None):
        return "doOperatorAuth error: %s" % ret

    # Check if list exists:
    list = activationxml.find("./%s" % (adNS("operatorURLList")))
    user_uuid = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("user"))).text

    if list is None: 
        x = etree.SubElement(activationxml.getroot(), etree.QName(NSMAP["adept"], "operatorURLList"), nsmap=NSMAP)
        etree.SubElement(x, etree.QName(NSMAP["adept"], "user")).text = user_uuid
        list = activationxml.find("./%s" % (adNS("operatorURLList")))
        if list is None: 
            return "Err, this list should not be none right now ..."
    
    etree.SubElement(list, etree.QName(NSMAP["adept"], "operatorURL")).text = operatorURL

    f = open(get_activation_xml_path(), "w")
    f.write("<?xml version=\"1.0\"?>\n")
    f.write(etree.tostring(activationxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))
    f.close()

    return None



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
        return None

    if not found:
        return None

    ret += "</adept:licenseServiceInfo>\n"
    ret += "</adept:rights>\n"

    return ret


def fulfill(acsm_file, do_notify = False):
    # Get pkcs12: 

    pkcs12 = None
    acsmxml = None
    try: 
        activationxml = etree.parse(get_activation_xml_path())
        adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
        pkcs12 = activationxml.find("./%s/%s" % (adNS("credentials"), adNS("pkcs12"))).text
    except: 
        return False, "Activation not found or invalid"

    if pkcs12 is None or len(pkcs12) == 0:
        return False, "Activation missing"

    try: 
        acsmxml = etree.parse(acsm_file)
    except: 
        return False, "ACSM not found or invalid"

    #print(etree.tostring(acsmxml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8"))

    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    dcNS = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

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


    fulfill_request = buildFulfillRequest(acsmxml)

    #print(fulfill_request)

    fulfill_request_xml = etree.fromstring(fulfill_request)
    # Sign the request:
    signature = sign_node(fulfill_request_xml)
    if (signature is None):
        return False, "Signing failed!"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    etree.SubElement(fulfill_request_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    # Get operator URL: 
    operatorURL = None
    try: 
        operatorURL = acsmxml.find("./%s" % (adNS("operatorURL"))).text.strip()
    except: 
        pass

    if (operatorURL is None or len(operatorURL) == 0):
        return False, "OperatorURL missing in ACSM"

    fulfillURL = operatorURL + "/Fulfill"

    ret = operatorAuth(fulfillURL)
    if (ret is not None):
        return False, "operatorAuth error: %s" % ret


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

    # Print fulfillmentResult
    #print(replyData)

    adobe_fulfill_response = etree.fromstring(replyData)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    licenseURL = adobe_fulfill_response.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("licenseURL"))).text

    if do_notify:
        print("Notifying server ...")
        success, response = performFulfillmentNotification(adobe_fulfill_response)
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
        updateLoanReturnData(adobe_fulfill_response)

    success, response = fetchLicenseServiceCertificate(licenseURL, operatorURL)

    if success is False: 
        return False, response

    return True, replyData



def updateLoanReturnData(fulfillmentResultToken):

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    dcNS = lambda tag: '{%s}%s' % ('http://purl.org/dc/elements/1.1/', tag)

    try: 
        loanToken = fulfillmentResultToken.find("./%s" % (adNS("loanToken")))
        if (loanToken is None):
            print("Loan token not found")
            return False
    except: 
        print("Loan token error")
        return False

    try: 
        loanID = loanToken.findall("./%s" % (adNS("loan")))[0].text
        if (loanID is None):
            print("Loan ID not found")
            return False

        operatorURL = loanToken.find("./%s" % (adNS("operatorURL"))).text
    except: 
        print("Loan ID error")
        return False

    book_name = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("metadata"), dcNS("title"))).text 

    userUUID = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("user"))).text
    deviceUUID = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("device"))).text

    loanid = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("fulfillment"))).text
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

    try: 
        import calibre_plugins.deacsm.prefs as prefs     # type: ignore
        deacsmprefs = prefs.DeACSM_Prefs()
    except: 
        print("Exception while reading config file")
        return False


    # Add all necessary information for a book return to the JSON array.
    # The config widget can then read this and present a list of not-yet-returned
    # books, and can then return them.
    # Also, the config widget is responsible for cleaning up that list.

    deacsmprefs["list_of_rented_books"].append({
            "book_name": book_name,
            "user": userUUID, 
            "device": deviceUUID, 
            "loanID": loanid, 
            "operatorURL": operatorURL, 
            "validUntil": dsp_until
        })

    deacsmprefs.writeprefs()

    return True


def tryReturnBook(bookData): 
    try: 
        user = bookData["user"]
        device = bookData["device"]
        loanID = bookData["loanID"]
        operatorURL = bookData["operatorURL"]
    except: 
        print("Invalid book data!")
        return False, "Invalid book data"

    req_data = "<?xml version=\"1.0\"?>"
    req_data += "<adept:loanReturn xmlns:adept=\"http://ns.adobe.com/adept\">"
    req_data += "<adept:user>%s</adept:user>" % (user)
    req_data += "<adept:device>%s</adept:device>" % (device)
    req_data += "<adept:loan>%s</adept:loan>" % (loanID)
    req_data += addNonce()
    req_data += "</adept:loanReturn>"

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    etree.register_namespace("adept", NSMAP["adept"])

    full_text_xml = etree.fromstring(req_data)

    signature = sign_node(full_text_xml)
    if (signature is None):
        print("SIGN ERROR!")
        return False, "Sign error"

    etree.SubElement(full_text_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

    print("Would notify server %s:" % (operatorURL + "/LoanReturn"))
    doc_send = "<?xml version=\"1.0\"?>\n" + etree.tostring(full_text_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
    # print(doc_send)


    retval = sendRequestDocu(doc_send, operatorURL + "/LoanReturn").decode("utf-8")

    if "<error" in retval: 
        print("Loan return failed: %s" % (retval))
        return False, retval
    elif "<envelope" in retval: 
        print("Loan return successful")
        return performFulfillmentNotification(etree.fromstring(retval), True, user=user, device=device)
    else: 
        print("Invalid loan return response: %s" % (retval))
        return False, retval



def performFulfillmentNotification(fulfillmentResultToken, forceOptional = False, user = None, device = None):

    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)

    reset = False
    try: 
        notifiers = fulfillmentResultToken.findall("./%s/%s" % (adNS("fulfillmentResult"), adNS("notify")))
    except:
        reset = True

    if len(notifiers) == 0: 
        try: 
            notifiers = fulfillmentResultToken.findall("./%s" % (adNS("notify")))
        except: 
            reset = True

    if len(notifiers) == 0: 
        try: 
            notifiers = fulfillmentResultToken.findall("./%s/%s" % (adNS("envelope"), adNS("notify")))
        except: 
            reset = True

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
            user = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("user"))).text
        
        if (device is None):
            device = fulfillmentResultToken.find("./%s/%s/%s/%s" % (adNS("fulfillmentResult"), adNS("resourceItemInfo"), adNS("licenseToken"), adNS("device"))).text

        
        full_text = "<adept:notification xmlns:adept=\"http://ns.adobe.com/adept\">"
        full_text += "<adept:user>%s</adept:user>" % user
        full_text += "<adept:device>%s</adept:device>" % device
        full_text += etree.tostring(body, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        full_text += addNonce()
        full_text += "</adept:notification>"

            
        NSMAP = { "adept" : "http://ns.adobe.com/adept" }
        etree.register_namespace("adept", NSMAP["adept"])

        full_text_xml = etree.fromstring(full_text)

        signature = sign_node(full_text_xml)
        if (signature is None):
            print("SIGN ERROR!")
            continue

        etree.SubElement(full_text_xml, etree.QName(NSMAP["adept"], "signature")).text = signature

        doc_send = "<?xml version=\"1.0\"?>\n" + etree.tostring(full_text_xml, encoding="utf-8", pretty_print=True, xml_declaration=False).decode("utf-8")
        
        # Debug: Print notify request
        #print(doc_send)

        code, msg = sendRequestDocuRC(doc_send, url)

        try: 
            msg = msg.decode("utf-8")
        except:
            pass

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


    if errmsg_crit == "": 
        return True, ""

    return False, errmsg




def fetchLicenseServiceCertificate(licenseURL: str, operatorURL: str):
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

    licenseServiceInfoReq = operatorURL + "/LicenseServiceInfo?licenseURL=" + licenseURL

    response = sendHTTPRequest(licenseServiceInfoReq).decode("utf-8")

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



