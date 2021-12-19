#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Use my own small RSA code so we don't have to include the huge
python3-rsa just for these small bits. 
The original code used blinding and this one doesn't, 
but we don't really care about side-channel attacks ...
'''

try:
    from Cryptodome.PublicKey import RSA
except ImportError:
    # Some distros still ship this as Crypto
    from Crypto.PublicKey import RSA

class CustomRSA: 

    def encrypt_for_adobe_signature(signing_key, message):
        key = RSA.importKey(signing_key)
        keylen = CustomRSA.byte_size(key.n)
        padded = CustomRSA.pad_message(message, keylen)
        payload = CustomRSA.transform_bytes2int(padded)
        encrypted = CustomRSA.normal_encrypt(key, payload)
        block = CustomRSA.transform_int2bytes(encrypted, keylen)
        return block

    def byte_size(number: int):
        return (number.bit_length() + 7) // 8

    def pad_message(message: bytes, target_len: int) -> bytes: 
        # Padding always uses 0xFF
        # Returns: 00 01 PADDING 00 MESSAGE

        max_message_length = target_len - 11
        message_length = len(message)

        if message_length > max_message_length:
            raise OverflowError("Message too long, has %d bytes but only space for %d" % (message_length, max_message_length))
        
        padding_len = target_len - message_length - 3

        return b"".join([b"\x00\x01", padding_len * b"\xff", b"\x00", message])

    def normal_encrypt(key, message: int):

        if message < 0 or message > key.n: 
            raise ValueError("Invalid message")

        encrypted = pow(message, key.d, key.n)
        return encrypted

    def transform_bytes2int(raw_bytes: bytes):
        return int.from_bytes(raw_bytes, "big", signed=False)

    def transform_int2bytes(number: int, fill_size: int = 0):
        if number < 0:
            raise ValueError("Negative number")
        
        if fill_size > 0:
            return number.to_bytes(fill_size, "big")
        
        bytes_needed = max(1, CustomRSA.byte_size(number))
        return number.to_bytes(bytes_needed, "big")