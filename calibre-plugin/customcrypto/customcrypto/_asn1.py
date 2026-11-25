"""
A minimal BER/DER reader, just enough to walk a PKCS#12 file.

This replaces the parts of asn1crypto that oscrypto uses for PKCS#12 parsing.
Instead of declarative schemas, callers navigate the tree by position and the
accessors below check the tag they expect.
"""

from ._compat import byte_at, int_from_bytes

SEQUENCE = 16

# PKCS#12 files nest about 12 levels deep. The limit keeps malformed input from
# hitting Python's recursion limit, so it raises ValueError like other errors.
_MAX_DEPTH = 32


class Element(object):
    """A single parsed TLV: tag class, constructed flag, tag number and contents."""

    __slots__ = ('cls', 'constructed', 'tag', 'contents', 'raw', 'depth')

    def __init__(self, cls, constructed, tag, contents, raw, depth):
        self.cls = cls                  # 0 universal, 1 application, 2 context, 3 private
        self.constructed = constructed
        self.tag = tag
        self.contents = contents        # value bytes, without header or end-of-contents
        self.raw = raw                  # the complete encoding of this element
        self.depth = depth              # nesting level within the data passed to load()

    def is_context(self, tag):
        return self.cls == 2 and self.tag == tag

    def _expect(self, tag, name):
        if self.cls != 0 or self.tag != tag:
            raise ValueError('Expected ASN.1 %s, found class %d tag %d' % (name, self.cls, self.tag))

    def children(self):
        if not self.constructed:
            raise ValueError('Expected a constructed ASN.1 value')
        result = []
        pos = 0
        while pos < len(self.contents):
            child, pos = _parse(self.contents, pos, self.depth + 1)
            result.append(child)
        return result

    def seq(self, min_len=0):
        """Returns the children of a SEQUENCE, requiring at least min_len of them"""
        self._expect(SEQUENCE, 'SEQUENCE')
        result = self.children()
        if len(result) < min_len:
            raise ValueError('ASN.1 SEQUENCE has %d elements, expected at least %d' % (len(result), min_len))
        return result

    def explicit(self, tag):
        """Unwraps an [n] EXPLICIT tagged value"""
        if not self.is_context(tag) or not self.constructed:
            raise ValueError('Expected ASN.1 [%d] EXPLICIT value' % tag)
        result = self.children()
        if len(result) != 1:
            raise ValueError('ASN.1 [%d] EXPLICIT value must contain exactly one element' % tag)
        return result[0]

    def int(self):
        self._expect(2, 'INTEGER')
        if self.constructed or not self.contents:
            raise ValueError('Invalid ASN.1 INTEGER')
        return int_from_bytes(self.contents, signed=True)

    def oid(self):
        self._expect(6, 'OBJECT IDENTIFIER')
        contents = bytearray(self.contents)
        if self.constructed or not contents or contents[-1] & 0x80:
            raise ValueError('Invalid ASN.1 OBJECT IDENTIFIER')
        arcs = []
        value = 0
        for byte in contents:
            value = (value << 7) | (byte & 0x7F)
            if not byte & 0x80:
                arcs.append(value)
                value = 0
        first = min(arcs[0] // 40, 2)
        return '.'.join(str(arc) for arc in [first, arcs[0] - 40 * first] + arcs[1:])

    def octets(self):
        """Value of an OCTET STRING (or an implicitly tagged one), joining BER chunks"""
        if self.cls != 2:
            self._expect(4, 'OCTET STRING')
        if not self.constructed:
            return self.contents
        return b''.join(chunk.octets() for chunk in self.children())


def load(data):
    """Parses the first ASN.1 element in data (trailing bytes are ignored, as in asn1crypto)"""
    return _parse(data, 0, 0)[0]


def _parse(data, pos, depth):
    if depth > _MAX_DEPTH:
        raise ValueError('ASN.1 values are nested too deeply')
    start = pos
    end = len(data)
    if end - pos < 2:
        raise ValueError('Insufficient data - ASN.1 header is truncated')

    first = byte_at(data, pos)
    pos += 1
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if pos >= end:
                raise ValueError('Insufficient data - ASN.1 tag is truncated')
            byte = byte_at(data, pos)
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    constructed = bool(first & 0x20)

    if pos >= end:
        raise ValueError('Insufficient data - ASN.1 length is truncated')
    length = byte_at(data, pos)
    pos += 1

    if length == 0x80:
        if not constructed:
            raise ValueError('Indefinite length is only allowed for constructed ASN.1 values')
        content_start = pos
        while data[pos:pos + 2] != b'\x00\x00':
            if pos >= end:
                raise ValueError('Insufficient data - missing ASN.1 end-of-contents')
            pos = _parse(data, pos, depth + 1)[1]
        return Element(first >> 6, True, tag, data[content_start:pos], data[start:pos + 2], depth), pos + 2

    if length & 0x80:
        num_bytes = length & 0x7F
        if pos + num_bytes > end:
            raise ValueError('Insufficient data - ASN.1 length is truncated')
        length = int_from_bytes(data[pos:pos + num_bytes])
        pos += num_bytes
    if pos + length > end:
        raise ValueError('Insufficient data - ASN.1 value is truncated')

    return Element(first >> 6, constructed, tag, data[pos:pos + length], data[start:pos + length], depth), pos + length
