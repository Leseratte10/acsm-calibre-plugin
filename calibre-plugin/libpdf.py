import os, zlib, base64
from lxml import etree


def read_reverse_order(file_name):
    # Open file for reading in binary mode
    with open(file_name, 'rb') as read_obj:
        # Move the cursor to the end of the file
        read_obj.seek(0, os.SEEK_END)
        # Get the current position of pointer i.e eof
        pointer_location = read_obj.tell()
        # Create a buffer to keep the last read line
        buffer = bytearray()
        # Loop till pointer reaches the top of the file
        while pointer_location >= 0:
            # Move the file pointer to the location pointed by pointer_location
            read_obj.seek(pointer_location)
            # Shift pointer location by -1
            pointer_location = pointer_location -1
            # read that byte / character
            new_byte = read_obj.read(1)
            # If the read byte is new line character then it means one line is read
            if new_byte == b'\n':
                # Fetch the line from buffer and yield it
                yield buffer.decode("latin-1")[::-1]
                # Reinitialize the byte array to save next line
                buffer = bytearray()
            else:
                # If last read character is not eol then add it in buffer
                buffer.extend(new_byte)
        # As file is read completely, if there is still data in buffer, then its the first line.
        if len(buffer) > 0:
            # Yield the first line too
            yield buffer.decode("latin-1")[::-1]

def deflate_and_base64_encode( string_val ):
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )

def prepare_string_from_xml(xmlstring, title, author):
    b64data = deflate_and_base64_encode(xmlstring.encode("utf-8")).decode("utf-8")

    adobe_fulfill_response = etree.fromstring(xmlstring)
    NSMAP = { "adept" : "http://ns.adobe.com/adept" }
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    resource = adobe_fulfill_response.find("./%s/%s" % (adNS("licenseToken"), adNS("resource"))).text

    return "<</Length 128/EBX_TITLE(%s)/Filter/EBX_HANDLER/EBX_AUTHOR(%s)/V 4/ADEPT_ID(%s)/EBX_BOOKID(%s)/ADEPT_LICENSE(%s)>>" % (title, author, resource, resource, b64data)

def patch_drm_into_pdf(filename_in, drm_string, filename_out):

    ORIG_FILE = filename_in

    trailer = ""
    trailer_idx = 0

    print("DRM data is %s" % (drm_string))

    for line in read_reverse_order(ORIG_FILE):
        trailer_idx += 1
        trailer = line + "\n" + trailer
        print("DEBUG: pdfdata[%d] = %s" % (trailer_idx, line))
        if (trailer_idx == 20):
            print("trailer_idx is very large (%d). Usually it's 10 or less. File might be corrupted." % trailer_idx)
        if (line == "trailer"): 
            print("Found trailer at idx %d" % (trailer_idx))
            break

    r_encrypt_offs1 = 0
    r_encrypt_offs2 = 0
    root_str = None
    next_startxref = False
    startxref = None

    for line in trailer.split('\n'):
        #print(line)
        if ("R/Encrypt" in line):
            root_str = line
            line_split = line.split(' ')
            next = 0
            for element in line_split:
                if element == "R/Encrypt":
                    next = 2
                    continue
                if next == 2:
                    r_encrypt_offs1 = element
                    next = 1
                    continue
                if next == 1: 
                    r_encrypt_offs2 = element
                    next = 0
                    continue
        if "startxref" in line: 
            next_startxref = True
            continue
        if next_startxref:
            startxref = line
            next_startxref = False
            continue
        

    filesize_str = str(os.path.getsize(ORIG_FILE))
    filesize_pad = filesize_str.zfill(10)


    additional_data = "\r"
    additional_data += r_encrypt_offs1 + " " + r_encrypt_offs2 + " " + "obj" + "\r"
    additional_data += drm_string
    additional_data += "\r"
    additional_data += "endobj"

    ptr = int(filesize_str) + len(additional_data)

    additional_data += "\rxref\r" + r_encrypt_offs1 + " " + str((int(r_encrypt_offs2) + 1)) + "\r"
    additional_data += filesize_pad + " 00000 n" + "\r\n"
    additional_data += "trailer"
    additional_data += "\r"

    arr_root_str = root_str.split('/')
    did_prev = False
    for elem in arr_root_str: 
        if elem.startswith("Prev"):
            did_prev = True
            additional_data += "Prev " + startxref
            #print("Replacing prev from '%s' to '%s'" % (elem, "Prev " + startxref))
        elif elem.startswith("ID[<"):
            additional_data += elem.replace("><", "> <")
        else:
            additional_data += elem
        additional_data += "/"

    if not did_prev:
        # remove two >> at end
        additional_data = additional_data[:-3]
        additional_data += "/Prev " + startxref + ">>" + "/"
        #print("Faking Prev %s" % startxref)

    additional_data = additional_data[:-1]

    additional_data += "\r" + "startxref\r" + str(ptr) + "\r" + "%%EOF"

    print("Appending DRM data: %s" % (additional_data))


    inp = open(ORIG_FILE, "rb")

    out = open(filename_out, "wb")
    out.write(inp.read())
    out.write(additional_data.encode("latin-1"))
    inp.close()
    out.close()
