'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, os, zlib, base64, time

class BackwardReader:

    def __init__(self, file):
        self.file = file


    def readlines(self):
        BLKSIZE = 4096
        # Move reader to the end of file
        self.file.seek(0, os.SEEK_END)
        if sys.version_info[0] >= 3:
            buffer = bytearray()
        else:
            buffer = ""

        while True:
            if sys.version_info[0] >= 3:
                pos_newline = buffer.rfind(bytes([0x0a]))
            else:
                pos_newline = buffer.rfind("\n")

            # Get the current position of the reader
            current_pos = self.file.tell()
            if pos_newline != -1:
                # Newline is found
                line = buffer[pos_newline+1:]
                buffer = buffer[:pos_newline]
                if sys.version_info[0] >= 3:
                    yield line.decode("latin-1")
                else:
                    yield line

            elif current_pos:
                # Need to fill the buffer
                to_read = min(BLKSIZE, current_pos)
                self.file.seek(current_pos-to_read, 0)
                buffer = self.file.read(to_read) + buffer
                self.file.seek(current_pos-to_read, 0)
                if current_pos is to_read:
                    if sys.version_info[0] >= 3:
                        buffer = bytes([0x0a]) + buffer
                    else:
                        buffer = "\n" + buffer
            else:
                # Start of file
                return




def trim_encrypt_string(encrypt):

    string_list = list(encrypt)
    strlen = len(encrypt)

    i = 0
    bracket_count = 0
    while (i < strlen):
        if string_list[i] == "<" and string_list[i+1] == "<":
            bracket_count += 1

        if string_list[i] == ">" and string_list[i+1] == ">":
            bracket_count -= 1

        if bracket_count == 0: 
            break

        i = i + 1

    len_to_use = i+2

    return encrypt[0:len_to_use]

def cleanup_encrypt_element(element):

    if element.startswith("ID[<"):
        element = element.replace("><", "> <")

    element = ' '.join(element.split())
    element = element.replace("[ ", "[").replace("] ", "]")

    return element




def deflate_and_base64_encode( string_val ):
    zlibbed_str = zlib.compress( string_val )
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode( compressed_string )

def update_ebx_with_keys(ebx_data, adept_license, ebx_bookid):

    b64data = deflate_and_base64_encode(adept_license.encode("utf-8")).decode("utf-8")

    ebx_new = ebx_data[:-2]
    ebx_new += "/EBX_BOOKID(%s)/ADEPT_LICENSE(%s)>>" % (ebx_bookid, b64data)

    return ebx_new


def find_ebx(filename_in):
    find_ebx_start = int(time.time() * 1000)
    i = 0

    fl = open(filename_in, "rb")
    br = BackwardReader(fl)

    for line in br.readlines():
        i = i + 1
        if "/EBX_HANDLER/" in line:
            find_ebx_end = int(time.time() * 1000)
            print("Found EBX after %d attempts - took %d ms" % (i, find_ebx_end - find_ebx_start))
            return line

    find_ebx_end = int(time.time() * 1000)
    print("Error: Did not find EBX_HANDLER - took %d ms" % (find_ebx_end - find_ebx_start))
    return None

def find_enc(filename_in):
    find_enc_start = int(time.time() * 1000)
    i = 0

    fl = open(filename_in, "rb")
    br = BackwardReader(fl)

    for line in br.readlines():
        i = i + 1
        is_encrypt_normal = "R/Encrypt" in line and "R/ID" in line
        is_encrypt_odd = "R" in line and "/Encrypt" in line and "/ID" in line
        if is_encrypt_normal or is_encrypt_odd:

            find_enc_end = int(time.time() * 1000)
            print("Found ENC after %d attempts - took %d ms" % (i, find_enc_end - find_enc_start))
            if is_encrypt_odd:
                print("Odd formatting of encryption blob?")
                print("If this doesn't work correctly please open a bug report.")
                
            return line
    
    find_enc_end = int(time.time() * 1000)
    print("Error: Did not find ENC - took %d ms" % (find_enc_end - find_enc_start))
    return None



def patch_drm_into_pdf(filename_in, adept_license_string, filename_out, ebx_bookid):

    drm_start_time = int(time.time() * 1000)

    trailer = ""
    trailer_idx = 0

    startxref_offset = 0
    prevline = ""


    fl = open(filename_in, "rb")
    br = BackwardReader(fl)

    print("Searching for startxref ...")
    for line in br.readlines():
        trailer_idx += 1
        trailer = line + "\n" + trailer

        #print ("LINE: " + line)

        if (trailer_idx > 10):
            print("Took more than 10 attempts to find startxref ...")
            return False
        
        if (line == "startxref"):
            startxref_offset = int(prevline)
            print("Got startxref: %d" % (startxref_offset))            
            break
        prevline = line



    r_encrypt_offs1 = 0
    r_encrypt_offs2 = 0

    encrypt = None


    encrypt = find_enc(filename_in)
    if encrypt is None:
        print("Error, enc not found")
        return False

    line_split = encrypt.split(' ')
    next = 0
    for element in line_split:
        if element == "R/Encrypt" or element == "/Encrypt":
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


    # read EBX element:
    ebx_elem = find_ebx(filename_in)
    
    if (ebx_elem is None):
        print("Err: EBX is None")
        return False

    
    print("")
    print("")
    print("Encryption handler:")
    print(encrypt)
    print("EBX handler:")
    print(ebx_elem)

    encrypt = trim_encrypt_string(encrypt)

    print("Trimmed encryption handler:")
    print(encrypt)

    ebx_elem = update_ebx_with_keys(ebx_elem, adept_license_string, ebx_bookid)

    print("Updated EBX handler not logged due to sensitive data")
    #print(ebx_elem)
        

    filesize_str = str(os.path.getsize(filename_in))
    filesize_pad = filesize_str.zfill(10)


    additional_data = "\r"
    additional_data += r_encrypt_offs1 + " " + r_encrypt_offs2 + " " + "obj" + "\r"
    additional_data += ebx_elem
    additional_data += "\r"
    additional_data += "endobj"

    ptr = int(filesize_str) + len(additional_data)

    additional_data += "\rxref\r" + r_encrypt_offs1 + " " + str((int(r_encrypt_offs2) + 1)) + "\r"
    additional_data += filesize_pad + " 00000 n" + "\r\n"
    additional_data += "trailer"
    additional_data += "\r"

    arr_root_str = encrypt.split('/')
    did_prev = False
    for elem in arr_root_str: 
        if elem.startswith("Prev"):
            did_prev = True
            additional_data += "Prev " + str(startxref_offset)
            #print("Replacing prev from '%s' to '%s'" % (elem, "Prev " + startxref))
        else:
            additional_data += cleanup_encrypt_element(elem)
        additional_data += "/"

    if not did_prev:
        # remove two >> at end
        additional_data = additional_data[:-3]
        additional_data += "/Prev " + str(startxref_offset) + ">>" + "/"
        #print("Faking Prev %s" % startxref)

    additional_data = additional_data[:-1]

    additional_data += "\r" + "startxref\r" + str(ptr) + "\r" + "%%EOF"

    #print("Appending DRM data: %s" % (additional_data))


    inp = open(filename_in, "rb")

    out = open(filename_out, "wb")
    out.write(inp.read())
    out.write(additional_data.encode("latin-1"))
    inp.close()
    out.close()

    drm_end_time = int(time.time() * 1000)

    print("Whole DRM patching took %d milliseconds." % (drm_end_time - drm_start_time))

    return True