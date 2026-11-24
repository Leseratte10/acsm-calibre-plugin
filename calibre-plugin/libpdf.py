'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, os, zlib, base64, time, shutil, re

class BackwardReader:
    """
    Read a binary file backwards, line by line, supporting all three 
    line endings (CR, LF, CRLF).
    """

    BLKSIZE = 4096

    def __init__(self, file):
        self.file = file

    def readlines(self):
        CR = b"\r"
        LF = b"\n"

        # Move reader to the end of file
        self.file.seek(0, os.SEEK_END)
        current_pos = self.file.tell()   # start of the not-yet-read region
        buffer = b""

        while True:
            # Last line terminator in the buffer, either CR or LF
            pos = max(buffer.rfind(LF), buffer.rfind(CR))

            # An LF at the very start of the buffer might be the second half
            # of a CRLF pair split across a block boundary, so we can't decide
            # yet whether the byte before it is a CR. Read more first.
            straddles = (pos == 0 and current_pos > 0
                         and buffer[:1] == LF)

            if pos != -1 and not straddles:
                # Line terminator found
                line = buffer[pos + 1:]
                if pos > 0 and buffer[pos:pos + 1] == LF \
                        and buffer[pos - 1:pos] == CR:
                    pos -= 1          # CRLF: drop the CR as well
                buffer = buffer[:pos]
                if sys.version_info[0] >= 3:
                    yield line.decode("latin-1")
                else:
                    yield line

            elif current_pos:
                # Need to fill the buffer
                to_read = min(self.BLKSIZE, current_pos)
                current_pos -= to_read
                self.file.seek(current_pos, os.SEEK_SET)
                buffer = self.file.read(to_read) + buffer
                if current_pos == 0:
                    # Sentinel so the first line of the file gets yielded
                    buffer = LF + buffer
            else:
                # Start of file
                return




def trim_encrypt_string(encrypt):
    """
    Removes leading or trailing junk data from the encrypt string. 
    """

    string_list = list(encrypt)
    strlen = len(encrypt)

    i = 0
    bracket_count = 0
    start_index = None
    # Each check looks at two characters, so stop one character early.
    while (i < strlen - 1):
        if string_list[i] == "<" and string_list[i+1] == "<":
            if start_index is None:
                # First bracket we've found
                start_index = i
            bracket_count += 1

        # Ignore ">>" in front of the dictionary.
        if start_index is not None and string_list[i] == ">" and string_list[i+1] == ">":
            bracket_count -= 1

        if bracket_count == 0 and start_index is not None: 
            break

        i = i + 1

    if start_index is None or bracket_count != 0:
        # No dictionary, or it isn't closed
        return ""

    len_to_use = i+2

    return encrypt[start_index:len_to_use]


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
            fl.close()
            return line

    find_ebx_end = int(time.time() * 1000)
    print("Error: Did not find EBX_HANDLER - took %d ms" % (find_ebx_end - find_ebx_start))
    fl.close()
    return None

def find_enc(filename_in):
    find_enc_start = int(time.time() * 1000)
    i = 0

    fl = open(filename_in, "rb")
    br = BackwardReader(fl)

    for line in br.readlines():
        i = i + 1
        lineparts = line.split('/')
        got_encrypt = got_id = False

        for part in lineparts:
            if part.startswith("Encrypt"):
                got_encrypt = True
            if part.startswith("ID"):
                got_id = True

        if not (got_encrypt and got_id):
            # Looks like that's not it.
            continue

        find_enc_end = int(time.time() * 1000)
        print("Found ENC after %d attempts - took %d ms" % (i, find_enc_end - find_enc_start))                
        fl.close()
        return line
    
    find_enc_end = int(time.time() * 1000)
    print("Error: Did not find ENC - took %d ms" % (find_enc_end - find_enc_start))
    fl.close()
    return None


def find_trailer(filename_in):
    """
    Returns the trailer dictionary in front of the last startxref, which can be
    spread over several lines. Returns None if there is no such trailer (e.g. with
    a cross-reference stream) or if it has no /Encrypt entry.
    """

    lines = None    # Lines between "trailer" and "startxref", last one first
    i = 0

    with open(filename_in, "rb") as fl:
        for line in BackwardReader(fl).readlines():
            i = i + 1

            if lines is None:
                # Still looking for startxref
                if line == "startxref":
                    lines = []
                elif i > 10:
                    return None
                continue

            if "trailer" in line:
                # The dictionary can start on the same line as the keyword.
                lines.append(line[line.index("trailer") + len("trailer"):])
                lines.reverse()
                trailer = "\n".join(lines)
                return trailer if "/Encrypt" in trailer else None

            if "endobj" in line or i > 100:
                # Something other than a trailer in front of startxref
                return None

            lines.append(line)

    return None



def patch_drm_into_pdf(filename_in, adept_license_string, filename_out, ebx_bookid):

    drm_start_time = int(time.time() * 1000)

    trailer = ""
    trailer_idx = 0

    startxref_offset = 0
    prevline = ""

    print("Searching for startxref ...")

    with open(filename_in, "rb") as fl:
        for line in BackwardReader(fl).readlines():
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



    encrypt = find_trailer(filename_in)
    if encrypt is None:
        # No trailer with /Encrypt in front of startxref (e.g. with a cross-reference
        # stream), so use the last line that contains /Encrypt and /ID instead.
        print("No trailer with /Encrypt in front of startxref, searching the file ...")
        encrypt = find_enc(filename_in)

    if encrypt is None:
        print("Error, enc not found")
        return False

    # Object and generation number of the encryption dictionary, from "/Encrypt 5 0 R".
    # There can be any whitespace between the parts, including line breaks.
    encrypt_ref = re.search(r"/Encrypt\s+(\d+)\s+(\d+)\s+R", encrypt)
    if encrypt_ref is None:
        print("Err: Didn't find encrypt offsets")
        return False

    r_encrypt_offs1 = encrypt_ref.group(1)
    r_encrypt_offs2 = encrypt_ref.group(2)


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
    if encrypt == "":
        print("Err: Trailer dictionary is incomplete")
        return False

    ebx_elem = update_ebx_with_keys(ebx_elem, adept_license_string, ebx_bookid)

    print("Updated EBX handler not logged due to sensitive data")
    #print(ebx_elem)
        

    # The appended data starts with "\r", so the new object begins one byte
    # after the end of the original file.
    obj_offset = os.path.getsize(filename_in) + 1


    additional_data = "\r"
    additional_data += r_encrypt_offs1 + " " + r_encrypt_offs2 + " " + "obj" + "\r"
    additional_data += ebx_elem
    additional_data += "\r"
    additional_data += "endobj"

    ptr = obj_offset + len(additional_data)

    # New xref subsection with a single entry for the rewritten object.
    # The entry has to use the generation number of that object.
    additional_data += "\rxref\r" + r_encrypt_offs1 + " 1\r"
    additional_data += "%010d %05d n\r\n" % (obj_offset, int(r_encrypt_offs2))
    additional_data += "trailer"
    additional_data += "\r"

    arr_root_str = encrypt.split('/')
    did_prev = False
    for elem in arr_root_str: 
        prev_is_last_element = False
        if elem.startswith("Prev"):
            did_prev = True
            additional_data += "Prev " + str(startxref_offset)
            prev_is_last_element = True
            #print("Replacing prev from '%s' to '%s'" % (elem, "Prev " + startxref))
        else:
            additional_data += cleanup_encrypt_element(elem)
        additional_data += "/"

    # Remove the final slash
    additional_data = additional_data[:-1]

    if not did_prev:
        # remove two >> at end, then append the Prev attribute.
        additional_data = additional_data[:-2]
        additional_data += "/Prev " + str(startxref_offset) + ">>"
        #print("Faking Prev %s" % startxref)
    elif prev_is_last_element:
        # Prev was the last element in the trailer so we need to close it.
        additional_data = additional_data + ">>"

    additional_data += "\r" + "startxref\r" + str(ptr) + "\r" + "%%EOF"

    #print("Appending DRM data: %s" % (additional_data))

    with open(filename_in, "rb") as inp, open(filename_out, "wb") as out:
        # Copy input file to output
        shutil.copyfileobj(inp, out)
        # Append encryption data.
        out.write(additional_data.encode("latin-1"))


    drm_end_time = int(time.time() * 1000)

    print("Whole DRM patching took %d milliseconds." % (drm_end_time - drm_start_time))

    return True