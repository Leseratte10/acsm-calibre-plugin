#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Copyright (c) 2021-2023 Leseratte10
This file is part of the ACSM Input Plugin by Leseratte10
ACSM Input Plugin for Calibre / acsm-calibre-plugin

For more information, see: 
https://github.com/Leseratte10/acsm-calibre-plugin
'''


'''
Use my own small RSA code so we don't have to include the huge
python3-rsa just for these small bits. 
The original code used blinding and this one doesn't, 
but we don't really care about side-channel attacks ...
'''

import sys

try:
    from Cryptodome.PublicKey import RSA
except ImportError:
    # Some distros still ship this as Crypto
    from Crypto.PublicKey import RSA

class CustomRSA: 

    @staticmethod
    def encrypt_for_adobe_signature(signing_key, message):
        key = RSA.importKey(signing_key)
        keylen = CustomRSA.byte_size(key.n)
        padded = CustomRSA.pad_message(message, keylen)
        payload = CustomRSA.transform_bytes2int(padded)
        encrypted = CustomRSA.normal_encrypt(key, payload)
        block = CustomRSA.transform_int2bytes(encrypted, keylen)
        return bytearray(block)

    @staticmethod
    def byte_size(number):
        # type: (int) -> int
        return (number.bit_length() + 7) // 8

    @staticmethod
    def pad_message(message, target_len): 
        # type: (bytes, int) -> bytes

        # Padding always uses 0xFF
        # Returns: 00 01 PADDING 00 MESSAGE

        max_message_length = target_len - 11
        message_length = len(message)

        if message_length > max_message_length:
            raise OverflowError("Message too long, has %d bytes but only space for %d" % (message_length, max_message_length))
        
        padding_len = target_len - message_length - 3

        ret = bytearray(b"".join([b"\x00\x01", padding_len * b"\xff", b"\x00"]))
        ret.extend(bytes(message))

        return ret

    @staticmethod
    def normal_encrypt(key, message):

        if message < 0 or message > key.n: 
            raise ValueError("Invalid message")

        encrypted = pow(message, key.d, key.n)
        return encrypted

    @staticmethod
    def py2_int_to_bytes(value, length, big_endian = True):
        result = []

        for i in range(0, length):
            result.append(value >> (i * 8) & 0xff)

        if big_endian:
            result.reverse()

        return result

    @staticmethod
    def py2_bytes_to_int(bytes, big_endian = True):
        # type: (bytes, bool) -> int

        my_bytes = bytes
        if not big_endian:
            my_bytes.reverse()

        result = 0
        for b in my_bytes:
            result = result * 256 + int(b)
        
        return result

    @staticmethod
    def transform_bytes2int(raw_bytes):
        # type: (bytes) -> int

        if sys.version_info[0] >= 3:
            return int.from_bytes(raw_bytes, "big", signed=False)

        return CustomRSA.py2_bytes_to_int(raw_bytes, True)


    @staticmethod
    def transform_int2bytes(number, fill_size = 0):
        # type: (int, int) -> bytes

        if number < 0:
            raise ValueError("Negative number")

        size = None
        
        if fill_size > 0:
            size = fill_size
        else:
            size = max(1, CustomRSA.byte_size(number))
        
        if sys.version_info[0] >= 3:
            return number.to_bytes(size, "big")
        
        return CustomRSA.py2_int_to_bytes(number, size, True)