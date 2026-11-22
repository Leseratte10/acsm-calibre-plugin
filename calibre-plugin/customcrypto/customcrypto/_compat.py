"""
The byte/integer conversions that differ between Python 2.7 and 3.
On Python 2, indexing a byte string returns a one-character string, and
int.from_bytes() and int.to_bytes() do not exist.
"""

import binascii
import sys

if sys.version_info < (3,):

    def byte_at(data, index):
        return ord(data[index])

    def int_from_bytes(data, signed=False):
        if not data:
            return 0
        value = int(binascii.hexlify(data), 16)
        if signed and ord(data[0]) & 0x80:
            value -= 1 << (8 * len(data))
        return value

    def int_to_bytes(value, width):
        # The * width has to be an int, and Python 2 sizes such as block_size are longs
        return binascii.unhexlify('%0*x' % (2 * int(width), value))

else:

    def byte_at(data, index):
        return data[index]

    def int_from_bytes(data, signed=False):
        return int.from_bytes(data, 'big', signed=signed)

    def int_to_bytes(value, width):
        return value.to_bytes(width, 'big')
