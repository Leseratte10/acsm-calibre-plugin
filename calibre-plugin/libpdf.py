'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, os, zlib, base64, time, shutil, re, collections, struct

class BackwardReader:
    """
    Read a binary file backwards, line by line, supporting all three 
    line endings (CR, LF, CRLF).
    """

    BLKSIZE = 4096

    def __init__(self, file):
        self.file = file

    def readlines(self):
        # Move reader to the end of file
        self.file.seek(0, os.SEEK_END)
        current_pos = self.file.tell()   # start of the not-yet-read region

        # Pieces of the line the reader is in, last piece first. They are joined
        # once the line is complete, so a line that spans many blocks isn't
        # copied and searched again for every block.
        pieces = []
        after_lf = False   # whether the data after current_pos starts with LF

        while current_pos:
            to_read = min(self.BLKSIZE, current_pos)
            current_pos -= to_read
            self.file.seek(current_pos, os.SEEK_SET)
            block = self.file.read(to_read)
            if sys.version_info[0] >= 3:
                # Latin-1 has one character per byte, so a block can be decoded on its own
                block = block.decode("latin-1")

            if after_lf and block.endswith("\r"):
                # The CR of a CRLF that is split across two blocks. The LF
                # already counted as the line ending.
                block = block[:-1]
            after_lf = block.startswith("\n")

            lines = re.split("\r\n|\r|\n", block)
            # The end of the block belongs to the line the reader is in
            pieces.append(lines.pop())
            if lines:
                # The block has a line ending, so that line is complete, and so
                # are the lines between the line endings of the block
                yield "".join(reversed(pieces))
                for line in reversed(lines[1:]):
                    yield line
                # The reader is now in the line in front of the first line ending
                pieces = [lines[0]]

        if pieces:
            # The first line of the file, unless the file is empty
            yield "".join(reversed(pieces))




def trim_encrypt_string(encrypt):
    """
    Removes leading or trailing junk data from the encrypt string, by returning
    the first complete dictionary in it. Returns "" if there is none.
    """

    strlen = len(encrypt)

    i = 0
    bracket_count = 0
    start_index = None
    while (i < strlen):
        if encrypt.startswith("<<", i):
            if start_index is None:
                # First bracket we've found
                start_index = i
            bracket_count += 1
            i = i + 2

        elif encrypt.startswith(">>", i):
            # Ignore ">>" in front of the dictionary.
            if start_index is not None:
                bracket_count -= 1
                if bracket_count == 0:
                    return encrypt[start_index:i+2]
            i = i + 2

        elif start_index is not None and encrypt[i] == "<":
            # Hex string. Skip it, so its closing ">" isn't taken for half of a ">>".
            end = encrypt.find(">", i)
            if end == -1:
                break
            i = end + 1

        elif start_index is not None and encrypt[i] == "(":
            # Literal string. Skip it, it can contain "<<" or ">>". Parentheses
            # in it are balanced, or escaped with a backslash.
            depth = 0
            while i < strlen:
                if encrypt[i] == "\\":
                    i = i + 1
                elif encrypt[i] == "(":
                    depth += 1
                elif encrypt[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i = i + 1
            i = i + 1

        else:
            i = i + 1

    # No dictionary, or it isn't closed
    return ""


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


def find_ebx(filename_in, obj_num, obj_gen):
    """
    Returns the EBX_HANDLER dictionary of the object obj_num obj_gen, which the
    /Encrypt entry of the trailer refers to. The header "N G obj" and the dictionary
    can be on the same line or on separate lines, and the dictionary can be spread
    over several lines. If the object is defined more than once (incremental updates),
    the last definition is used. Returns None if there is no such object.
    """

    find_ebx_start = int(time.time() * 1000)
    i = 0

    # Object header "N G obj". It has to be preceded by whitespace or the start of the
    # line, so a header of e.g. object 15 doesn't match object 5.
    header = re.compile(r"(?:^|(?<=\s))%d\s+%d\s+obj(?![^\s<\[(/%%])" % (int(obj_num), int(obj_gen)))

    # The lines after the current one, next line first. The dictionary is short, so
    # only a few lines are kept, also when the reader is in a large stream.
    following = collections.deque(maxlen=50)

    with open(filename_in, "rb") as fl:
        for line in BackwardReader(fl).readlines():
            i = i + 1
            # Check for "obj" first, the regex is slower and most lines don't contain it.
            match = header.search(line) if "obj" in line else None
            if match is not None:
                obj_data = line[match.end():] + "\n" + "\n".join(following)
                if obj_data.lstrip().startswith("<<"):
                    ebx = trim_encrypt_string(obj_data)
                    if re.search(r"/Filter\s*/EBX_HANDLER(?![^\s<\[(/%>])", ebx):
                        find_ebx_end = int(time.time() * 1000)
                        print("Found EBX after %d attempts - took %d ms" % (i, find_ebx_end - find_ebx_start))
                        return ebx
                # Not the encryption dictionary, e.g. the header was text in a stream.
                # Keep searching for an earlier definition.

            following.appendleft(line)

    find_ebx_end = int(time.time() * 1000)
    print("Error: Did not find EBX_HANDLER in object %s %s - took %d ms" % (obj_num, obj_gen, find_ebx_end - find_ebx_start))
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



    # In a file with a cross-reference stream (PDF 1.5+), startxref points to that stream,
    # and its dictionary has the trailer entries. Otherwise it points to an xref table.
    with open(filename_in, "rb") as fl:
        fl.seek(startxref_offset)
        xref_data = fl.read(65536)
    if sys.version_info[0] >= 3:
        xref_data = xref_data.decode("latin-1")

    encrypt = None
    if re.match(r"\s*\d+\s+\d+\s+obj\s*<<", xref_data):
        encrypt = trim_encrypt_string(xref_data)
        if not re.search(r"/Type\s*/XRef(?![^\s<\[(/%>])", encrypt):
            encrypt = None
    xref_stream = encrypt is not None

    if encrypt is None:
        encrypt = find_trailer(filename_in)
    if encrypt is None:
        # No trailer with /Encrypt in front of startxref, so use the
        # last line that contains /Encrypt and /ID instead.
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


    # read EBX element from the object that /Encrypt refers to, as that's the
    # object number the new EBX element is written with:
    ebx_elem = find_ebx(filename_in, r_encrypt_offs1, r_encrypt_offs2)
    
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

    if xref_stream:
        # The file uses cross-reference streams, so append one as well, with entries for
        # the rewritten object and for the stream itself. Its dictionary only gets the
        # entries of a trailer from the old one, not the ones that describe the old stream.
        size = re.search(r"/Size\s+(\d+)", encrypt)
        if size is None:
            print("Err: Cross-reference stream has no /Size")
            return False
        xref_num = max(int(size.group(1)), int(r_encrypt_offs1) + 1)

        rows = struct.pack(">BQH", 1, obj_offset, int(r_encrypt_offs2)) + struct.pack(">BQH", 1, ptr, 0)
        # As text, like the rest of additional_data. In Python 2 that's unicode too (because
        # of the base64 data in the EBX dictionary), so a str with bytes >= 0x80 can't be
        # added to it.
        rows = rows.decode("latin-1")

        stream_dict = "<</Type/XRef/Size %d/W[1 8 2]/Index[%s 1 %d 1]/Length %d" % (xref_num + 1, r_encrypt_offs1, xref_num, len(rows))
        for key in ("Root", "Info"):
            ref = re.search(r"/%s\s+(\d+)\s+(\d+)\s+R" % key, encrypt)
            if ref is not None:
                stream_dict += "/%s %s %s R" % (key, ref.group(1), ref.group(2))
        stream_dict += "/Encrypt %s %s R" % (r_encrypt_offs1, r_encrypt_offs2)
        # Two hex or literal strings. Literal strings can contain "]", but parentheses in
        # them have to be escaped here. The ID is needed for decryption, so it has to be found.
        string = r"(?:<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\()])*\))"
        file_id = re.search(r"/ID\s*(\[\s*%s\s*%s\s*\])" % (string, string), encrypt, re.S)
        if file_id is None:
            print("Err: Cross-reference stream has no /ID that can be copied")
            return False
        stream_dict += "/ID" + file_id.group(1)
        stream_dict += "/Prev %d>>" % startxref_offset

        additional_data += "\r%d 0 obj\r%s\rstream\r\n%s\rendstream\rendobj" % (xref_num, stream_dict, rows)
        additional_data += "\rstartxref\r" + str(ptr) + "\r%%EOF"

        with open(filename_in, "rb") as inp, open(filename_out, "wb") as out:
            shutil.copyfileobj(inp, out)
            out.write(additional_data.encode("latin-1"))

        print("Whole DRM patching took %d milliseconds." % (int(time.time() * 1000) - drm_start_time))
        return True

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