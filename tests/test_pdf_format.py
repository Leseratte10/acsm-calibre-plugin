#!/usr/bin/python3 
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2026 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''

import sys, os
sys.path.append("../calibre-plugin")


import unittest
from acsm_input.libpdf import trim_encrypt_string, cleanup_encrypt_element, deflate_and_base64_encode  # type: ignore
from acsm_input.libpdf import BackwardReader, patch_drm_into_pdf  # type: ignore

import io, re, shutil, tempfile

try:
    # Python 2: print() writes byte strings there, which io.StringIO doesn't accept.
    from StringIO import StringIO  # type: ignore
except ImportError:
    from io import StringIO


def read_lines_backwards(data):
    # type: (bytes) -> list
    return list(BackwardReader(io.BytesIO(data)).readlines())

def expected_lines_backwards(data):
    # type: (bytes) -> list
    # The lines BackwardReader should return for data: split at CRLF, CR or LF, last line first.
    lines = re.split(b"\r\n|\r|\n", data)
    lines.reverse()
    if sys.version_info[0] >= 3:
        lines = [line.decode("latin-1") for line in lines]
    return lines

def build_test_pdf(trailer, eol=b"\n", gen=0, trailer_on_keyword_line=False, trailer_lines=None):
    # type: (bytes, bytes, int, bool, list) -> tuple
    # Builds a minimal PDF with a correct xref table and returns (content, xref offset).
    # Object 5 is the EBX_HANDLER encryption dictionary that patch_drm_into_pdf looks for.
    # The trailer dictionary is written on its own line, on the same line as the
    # "trailer" keyword (trailer_on_keyword_line), or spread over several lines (trailer_lines).

    objects = [
        (1, 0, b"<</Type/Catalog/Pages 2 0 R>>"),
        (2, 0, b"<</Type/Pages/Kids[]/Count 0>>"),
        (5, gen, b"<</Filter/EBX_HANDLER/V 4/R 4/Length 128>>"),
    ]

    pdf = b"%PDF-1.4" + eol
    offsets = {}
    for num, obj_gen, body in objects:
        offsets[num] = (len(pdf), obj_gen)
        pdf += b"%d %d obj" % (num, obj_gen) + eol + body + eol + b"endobj" + eol

    xref_offset = len(pdf)
    pdf += b"xref" + eol + b"0 6" + eol + b"0000000000 65535 f\r\n"
    for num in range(1, 6):
        if num in offsets:
            pdf += b"%010d %05d n\r\n" % offsets[num]
        else:
            pdf += b"0000000000 00000 f\r\n"

    if trailer_lines is not None:
        pdf += b"trailer" + eol + eol.join(trailer_lines) + eol
    elif trailer_on_keyword_line:
        pdf += b"trailer" + trailer + eol
    else:
        pdf += b"trailer" + eol + trailer + eol

    pdf += b"startxref" + eol + b"%d" % xref_offset + eol + b"%%EOF" + eol
    return pdf, xref_offset


class TestPDFFormat(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self): 
        pass

    def forcefail(self):
        self.assertEqual(1, 2, "force fail")

    def test_pdf_trimEncrypt(self): 
        '''Check if PDF encryption string trimming code is working properly'''

        input = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>AppendedData"
        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"

        self.assertEqual(trim_encrypt_string(input), output, "trim didn't remove trailing junk")

        input = "PrefixJunk123<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"
        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"

        self.assertEqual(trim_encrypt_string(input), output, "trim didn't remove leading junk")

    def test_pdf_cleanupEncrypt(self): 
        '''Check if PDF encryption string spacing code is working properly'''

        self.assertEqual(cleanup_encrypt_element("ID[<1111><2222>]"),       "ID[<1111> <2222>]", "angle bracket spacing invalid")
        self.assertEqual(cleanup_encrypt_element("ID[  <1111> <2222>]  "),  "ID[<1111> <2222>]", "square bracket spacing invalid")

    def test_pdf_deflateCompression(self): 
        '''Check if PDF rights.xml deflare code is working properly'''

        self.assertEqual(deflate_and_base64_encode(b""),                  b"AwA=",                  "deflate code error in empty string")
        self.assertEqual(deflate_and_base64_encode(b"Hello world"),       b"80jNyclXKM8vykkBAA==",  "deflate code error")
        self.assertEqual(deflate_and_base64_encode(b"Example AAAAAAAAA"), b"c61IzC3ISVVwhAEA",      "deflate code error")

    def test_pdf_backwardReaderLineEndings(self):
        '''Check if the backward line reader supports LF, CRLF, CR and mixed line endings'''

        blksize = BackwardReader.BLKSIZE

        for name, eols in [("LF", [b"\n"]), ("CRLF", [b"\r\n"]), ("CR", [b"\r"]), ("mixed", [b"\n", b"\r\n", b"\r"])]:
            parts = []
            for i in range(600):
                parts.append(b"line %d" % i + b"x" * (i % 23))
                parts.append(eols[i % len(eols)])
            data = b"".join(parts)

            # Cut the data at sizes around the block size, so lines and CRLF pairs end up split across blocks.
            for size in [1, 2, blksize - 1, blksize, blksize + 1, 2 * blksize, 2 * blksize + 1, len(data)]:
                self.assertEqual(read_lines_backwards(data[:size]), expected_lines_backwards(data[:size]),
                                 "%s line endings read incorrectly for %d bytes" % (name, size))

    def test_pdf_backwardReaderSplitCRLF(self):
        '''Check if the backward line reader handles a CRLF that is split between two blocks'''

        # The reader starts with the last block, so let that block begin with the LF
        # and put the matching CR at the end of the block before it.
        data = b"first line\r" + b"\n" + b"A" * (BackwardReader.BLKSIZE - 1)
        self.assertEqual(read_lines_backwards(data), expected_lines_backwards(data), "split CRLF was read as two line breaks")

    def test_pdf_trimEncryptTrailerKeyword(self):
        '''Check if PDF encryption string trimming removes the trailer keyword or whitespace in front of it'''

        output = "<</Root 1 0 R/Info 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]/Size 3>>"
        for prefix in ["trailer", "trailer ", "  "]:
            self.assertEqual(trim_encrypt_string(prefix + output), output, "trim didn't remove the prefix '%s'" % prefix)

    def test_pdf_trimEncryptIncomplete(self):
        '''Check if PDF encryption string trimming rejects incomplete dictionaries'''

        for encrypt in ["/Encrypt 1 0 R/ID[<1111><2222>]>>", "<</Root 1 0 R/Encrypt 1 0 R/ID[<1111><2222>]", "<", ">"]:
            self.assertEqual(trim_encrypt_string(encrypt), "", "trim didn't reject '%s'" % encrypt)

        # ">>" in front of the dictionary belongs to something else.
        self.assertEqual(trim_encrypt_string(">> <</Root 1 0 R>>"), "<</Root 1 0 R>>", "trim didn't skip '>>' in front of the dictionary")

    def test_pdf_trimEncryptNested(self):
        '''Check if PDF encryption string trimming handles nested dictionaries and strings'''

        for output in ["<</Size 3/Encrypt 1 0 R/Info<</Title(x)>>>>",
                       "<</Size 3/Info<</A<</B 1>>>>/Encrypt 1 0 R>>",
                       "<</Size 3/Encrypt 1 0 R/Foo<1234>>>",
                       "<</Size 3/Encrypt 1 0 R/Foo(a >> b)>>",
                       "<</Size 3/Encrypt 1 0 R/Foo(a \\) >> b)>>",
                       "<</Size 3/Encrypt 1 0 R/Foo(a (b >>) c)>>"]:
            self.assertEqual(trim_encrypt_string(output + ">>junk"), output, "trim cut '%s' at the wrong place" % output)


    # Helpers for the tests that patch a complete PDF:

    def patch_pdf(self, pdf):
        # type: (bytes) -> tuple
        # Runs patch_drm_into_pdf on a PDF with the given content.
        # Returns its return value and the content of the output file (None if there is none).

        if getattr(self, "pdf_tmpdir", None) is None:
            self.pdf_tmpdir = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, self.pdf_tmpdir, True)

        self.pdf_counter = getattr(self, "pdf_counter", 0) + 1
        file_in = os.path.join(self.pdf_tmpdir, "in%d.pdf" % self.pdf_counter)
        file_out = os.path.join(self.pdf_tmpdir, "out%d.pdf" % self.pdf_counter)

        with open(file_in, "wb") as f:
            f.write(pdf)

        # patch_drm_into_pdf logs a lot, keep that out of the test output.
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            ret = patch_drm_into_pdf(file_in, "<adept:rights/>", file_out, "urn:uuid:00000000-0000-0000-0000-000000000000")
        finally:
            sys.stdout = old_stdout

        output = None
        if os.path.exists(file_out):
            with open(file_out, "rb") as f:
                output = f.read()

        return ret, output

    def get_appended_trailer(self, pdf, output):
        # type: (bytes, bytes) -> tuple
        # Returns the new trailer dictionary and the startxref value that the patch appended to pdf.
        match = re.search(br"trailer\r(.*)\rstartxref\r(\d+)\r%%EOF$", output[len(pdf):], re.S)
        self.assertIsNotNone(match, "patched PDF has no new trailer")
        return match.group(1), int(match.group(2))

    def check_patched_trailer(self, trailer, expected_trailer, msg, **pdf_args):
        # type: (bytes, bytes, str, ...) -> tuple
        # Patches a test PDF that has the given trailer and checks the new trailer.
        # %d in expected_trailer is replaced with the xref offset of the original file (for /Prev).
        # Returns the original PDF and the patched one.

        pdf, xref_offset = build_test_pdf(trailer, **pdf_args)
        ret, output = self.patch_pdf(pdf)

        self.assertTrue(ret, msg + ": patching failed")
        self.assertEqual(output[:len(pdf)], pdf, msg + ": original PDF data was changed")
        new_trailer, _ = self.get_appended_trailer(pdf, output)
        self.assertEqual(new_trailer, expected_trailer % xref_offset, msg + ": wrong trailer")

        return pdf, output


    def test_pdf_patchTrailerNoPrev(self):
        '''Check if patching adds /Prev to a trailer that doesn't have one'''

        self.check_patched_trailer(
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]>>",
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
            "trailer without /Prev")

    def test_pdf_patchTrailerPrevInMiddle(self):
        '''Check if patching replaces /Prev in the middle of the trailer'''

        self.check_patched_trailer(
            b"<</Size 6/Prev 9/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]>>",
            b"<</Size 6/Prev %d/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]>>",
            "trailer with /Prev in the middle")

    def test_pdf_patchTrailerPrevLast(self):
        '''Check if patching replaces /Prev when it is the last key of the trailer'''

        self.check_patched_trailer(
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]/Prev 9>>",
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
            "trailer with /Prev as the last key")

    def test_pdf_patchLineEndings(self):
        '''Check if PDFs with LF, CRLF or CR line endings can be patched'''

        for name, eol in [("LF", b"\n"), ("CRLF", b"\r\n"), ("CR", b"\r")]:
            self.check_patched_trailer(
                b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]>>",
                b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
                name + " line endings", eol=eol)

    def test_pdf_patchTrailerOnKeywordLine(self):
        '''Check if PDFs with the trailer dictionary on the same line as the trailer keyword can be patched'''

        for prefix, name in [(b"", "trailer<<"), (b" ", "trailer <<")]:
            self.check_patched_trailer(
                prefix + b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]>>",
                b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
                name, trailer_on_keyword_line=True)

    def test_pdf_patchEncryptPosition(self):
        '''Check if patching finds the /Encrypt reference at any position in the trailer'''

        cases = [
            (b"<</Root 1 0 R/Size 6/Encrypt 5 0 R/ID[<aa><bb>]>>",
             b"<</Root 1 0 R/Size 6/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>", "/Encrypt after a number"),
            (b"<</Size 6/Root 1 0 R/ID[<aa><bb>]/Encrypt 5 0 R>>",
             b"<</Size 6/Root 1 0 R/ID[<aa> <bb>]/Encrypt 5 0 R/Prev %d>>", "/Encrypt as the last key"),
        ]
        for trailer, expected_trailer, name in cases:
            pdf, output = self.check_patched_trailer(trailer, expected_trailer, name)
            self.assertIn(b"\r5 0 obj\r", output[len(pdf):], name + ": encryption object wasn't rewritten")

    def test_pdf_patchOffsets(self):
        '''Check if the new xref entry and startxref of a patched PDF point to the right positions'''

        pdf, output = self.check_patched_trailer(
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]>>",
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
            "offsets")

        xref = re.search(br"\rxref\r(\d+ \d+)\r(\d{10}) (\d{5}) n\r\n", output[len(pdf):])
        self.assertIsNotNone(xref, "patched PDF has no new xref section")
        self.assertEqual(xref.group(1), b"5 1", "xref subsection should contain exactly object 5")
        self.assertTrue(output[int(xref.group(2)):].startswith(b"5 0 obj"), "xref entry doesn't point to the object")

        _, startxref = self.get_appended_trailer(pdf, output)
        self.assertTrue(output[startxref:].startswith(b"xref"), "startxref doesn't point to the xref section")

    def test_pdf_patchGenerationNotZero(self):
        '''Check if PDFs whose encryption object has a generation other than 0 can be patched'''

        pdf, output = self.check_patched_trailer(
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 1 R/ID[<aa><bb>]>>",
            b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 1 R/ID[<aa> <bb>]/Prev %d>>",
            "generation 1", gen=1)

        xref = re.search(br"\rxref\r(\d+ \d+)\r(\d{10}) (\d{5}) n\r\n", output[len(pdf):])
        self.assertIsNotNone(xref, "patched PDF has no new xref section")
        self.assertEqual(xref.group(1), b"5 1", "xref subsection should contain exactly one entry")
        self.assertEqual(xref.group(3), b"00001", "xref entry should use the object's generation")
        self.assertTrue(output[int(xref.group(2)):].startswith(b"5 1 obj"), "xref entry doesn't point to the object")

    def test_pdf_patchEncryptExtraWhitespace(self):
        '''Check if PDFs with extra whitespace in the /Encrypt reference can be patched'''

        for encrypt in [b"/Encrypt  5 0 R", b"/Encrypt 5  0  R", b"/Encrypt\t5\t0\tR", b"/Encrypt 5 0 R "]:
            pdf, output = self.check_patched_trailer(
                b"<</Size 6/Root 1 0 R/Info 2 0 R" + encrypt + b"/ID[<aa><bb>]>>",
                b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>",
                repr(encrypt))
            self.assertIn(b"\r5 0 obj\r", output[len(pdf):], repr(encrypt) + ": encryption object written with the wrong number")

    def test_pdf_patchTrailerAcrossLines(self):
        '''Check if PDFs whose trailer dictionary is spread over several lines can be patched'''

        expected_trailer = b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa> <bb>]/Prev %d>>"
        cases = [
            ("/Encrypt on the next line", [b"<</Size 6/Root 1 0 R/Info 2 0 R", b"/Encrypt 5 0 R/ID[<aa><bb>]>>"]),
            (">> on its own line",        [b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]", b">>"]),
            ("/Prev in front of >>",      [b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0 R/ID[<aa><bb>]/Prev 9", b">>"]),
            ("split /Encrypt reference",  [b"<</Size 6/Root 1 0 R/Info 2 0 R/Encrypt 5 0", b"R/ID[<aa><bb>]>>"]),
            ("one key per line",          [b"<<", b"/Size 6", b"/Root 1 0 R", b"/Info 2 0 R", b"/Encrypt 5 0 R", b"/ID[<aa><bb>]", b">>"]),
        ]

        for eol_name, eol in [("LF", b"\n"), ("CRLF", b"\r\n"), ("CR", b"\r")]:
            for name, lines in cases:
                self.check_patched_trailer(None, expected_trailer, "%s, %s" % (name, eol_name), trailer_lines=lines, eol=eol)

            # The dictionary can also start on the line of the trailer keyword.
            self.check_patched_trailer(
                b"<</Size 6/Root 1 0 R/Info 2 0 R" + eol + b"/Encrypt 5 0 R/ID[<aa><bb>]>>", expected_trailer,
                "dictionary starting on the keyword line, " + eol_name, trailer_on_keyword_line=True, eol=eol)

    def test_pdf_patchTrailerNestedValues(self):
        '''Check if PDFs whose trailer ends with a nested dictionary or a string can be patched'''

        start = b"<</Size 6/Root 1 0 R/Encrypt 5 0 R/ID[<aa><bb>]"
        expected_start = b"<</Size 6/Root 1 0 R/Encrypt 5 0 R/ID[<aa> <bb>]"
        for value, name in [(b"/Info<</Title(x)>>", "nested dictionary"), (b"/Foo<1234>", "hex string"), (b"/Foo(a>>b)", "string with >>")]:
            self.check_patched_trailer(start + value + b">>", expected_start + value + b"/Prev %d>>", name + " at the end")

