#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Most of the code in this file has been taken from adobekey.pyw written by i♥cabbages
# adobekey.pyw, version 7.0
# Copyright © 2009-2020 i♥cabbages, Apprentice Harper et al.
# Released under the terms of the GNU General Public Licence, version 3
# <http://www.gnu.org/licenses/>


from ctypes import windll, c_char_p, c_wchar_p, c_uint, POINTER, byref, \
    create_unicode_buffer, create_string_buffer, CFUNCTYPE, \
    string_at, Structure, c_void_p, cast, c_size_t, memmove

from ctypes.wintypes import LPVOID, DWORD, BOOL
import struct

try:
    import winreg
except ImportError:
    import _winreg as winreg


MAX_PATH = 255

kernel32 = windll.kernel32
advapi32 = windll.advapi32
crypt32 = windll.crypt32

def GetSystemDirectory():
    GetSystemDirectoryW = kernel32.GetSystemDirectoryW
    GetSystemDirectoryW.argtypes = [c_wchar_p, c_uint]
    GetSystemDirectoryW.restype = c_uint
    def GetSystemDirectory():
        buffer = create_unicode_buffer(MAX_PATH + 1)
        GetSystemDirectoryW(buffer, len(buffer))
        return buffer.value
    return GetSystemDirectory
GetSystemDirectory = GetSystemDirectory()

def GetVolumeSerialNumber():
    GetVolumeInformationW = kernel32.GetVolumeInformationW
    GetVolumeInformationW.argtypes = [c_wchar_p, c_wchar_p, c_uint,
                                        POINTER(c_uint), POINTER(c_uint),
                                        POINTER(c_uint), c_wchar_p, c_uint]
    GetVolumeInformationW.restype = c_uint
    def GetVolumeSerialNumber(path):
        vsn = c_uint(0)
        GetVolumeInformationW(
            path, None, 0, byref(vsn), None, None, None, 0)
        return vsn.value
    return GetVolumeSerialNumber
GetVolumeSerialNumber = GetVolumeSerialNumber()

def GetUserName():
    GetUserNameW = advapi32.GetUserNameW
    GetUserNameW.argtypes = [c_wchar_p, POINTER(c_uint)]
    GetUserNameW.restype = c_uint
    def GetUserName():
        buffer = create_unicode_buffer(32)
        size = c_uint(len(buffer))
        while not GetUserNameW(buffer, byref(size)):
            buffer = create_unicode_buffer(len(buffer) * 2)
            size.value = len(buffer)
        return buffer.value.encode('utf-16-le')[::2]
    return GetUserName
GetUserName = GetUserName()

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000

def VirtualAlloc():
    _VirtualAlloc = kernel32.VirtualAlloc
    _VirtualAlloc.argtypes = [LPVOID, c_size_t, DWORD, DWORD]
    _VirtualAlloc.restype = LPVOID
    def VirtualAlloc(addr, size, alloctype=(MEM_COMMIT | MEM_RESERVE),
                        protect=PAGE_EXECUTE_READWRITE):
        return _VirtualAlloc(addr, size, alloctype, protect)
    return VirtualAlloc
VirtualAlloc = VirtualAlloc()

MEM_RELEASE = 0x8000

def VirtualFree():
    _VirtualFree = kernel32.VirtualFree
    _VirtualFree.argtypes = [LPVOID, c_size_t, DWORD]
    _VirtualFree.restype = BOOL
    def VirtualFree(addr, size=0, freetype=MEM_RELEASE):
        return _VirtualFree(addr, size, freetype)
    return VirtualFree
VirtualFree = VirtualFree()

class NativeFunction(object):
    def __init__(self, restype, argtypes, insns):
        self._buf = buf = VirtualAlloc(None, len(insns))
        memmove(buf, insns, len(insns))
        ftype = CFUNCTYPE(restype, *argtypes)
        self._native = ftype(buf)

    def __call__(self, *args):
        return self._native(*args)

    def __del__(self):
        if self._buf is not None:
            VirtualFree(self._buf)
            self._buf = None

if struct.calcsize("P") == 4:
    CPUID0_INSNS = (
        b"\x53"             # push   %ebx
        b"\x31\xc0"         # xor    %eax,%eax
        b"\x0f\xa2"         # cpuid
        b"\x8b\x44\x24\x08" # mov    0x8(%esp),%eax
        b"\x89\x18"         # mov    %ebx,0x0(%eax)
        b"\x89\x50\x04"     # mov    %edx,0x4(%eax)
        b"\x89\x48\x08"     # mov    %ecx,0x8(%eax)
        b"\x5b"             # pop    %ebx
        b"\xc3"             # ret
    )
    CPUID1_INSNS = (
        b"\x53"             # push   %ebx
        b"\x31\xc0"         # xor    %eax,%eax
        b"\x40"             # inc    %eax
        b"\x0f\xa2"         # cpuid
        b"\x5b"             # pop    %ebx
        b"\xc3"             # ret
    )
else:
    CPUID0_INSNS = (
        b"\x49\x89\xd8"     # mov    %rbx,%r8
        b"\x49\x89\xc9"     # mov    %rcx,%r9
        b"\x48\x31\xc0"     # xor    %rax,%rax
        b"\x0f\xa2"         # cpuid
        b"\x4c\x89\xc8"     # mov    %r9,%rax
        b"\x89\x18"         # mov    %ebx,0x0(%rax)
        b"\x89\x50\x04"     # mov    %edx,0x4(%rax)
        b"\x89\x48\x08"     # mov    %ecx,0x8(%rax)
        b"\x4c\x89\xc3"     # mov    %r8,%rbx
        b"\xc3"             # retq
    )
    CPUID1_INSNS = (
        b"\x53"             # push   %rbx
        b"\x48\x31\xc0"     # xor    %rax,%rax
        b"\x48\xff\xc0"     # inc    %rax
        b"\x0f\xa2"         # cpuid
        b"\x5b"             # pop    %rbx
        b"\xc3"             # retq
    )

def cpuid0():
    _cpuid0 = NativeFunction(None, [c_char_p], CPUID0_INSNS)
    buf = create_string_buffer(12)
    def cpuid0():
        _cpuid0(buf)
        return buf.raw
    return cpuid0
cpuid0 = cpuid0()

cpuid1 = NativeFunction(c_uint, [], CPUID1_INSNS)

class DataBlob(Structure):
    _fields_ = [('cbData', c_uint),
                ('pbData', c_void_p)]
DataBlob_p = POINTER(DataBlob)

def CryptUnprotectData():
    _CryptUnprotectData = crypt32.CryptUnprotectData
    _CryptUnprotectData.argtypes = [DataBlob_p, c_wchar_p, DataBlob_p,
                                    c_void_p, c_void_p, c_uint, DataBlob_p]
    _CryptUnprotectData.restype = c_uint
    def CryptUnprotectData(indata, entropy):
        indatab = create_string_buffer(indata)
        indata = DataBlob(len(indata), cast(indatab, c_void_p))
        entropyb = create_string_buffer(entropy)
        entropy = DataBlob(len(entropy), cast(entropyb, c_void_p))
        outdata = DataBlob()
        if not _CryptUnprotectData(byref(indata), None, byref(entropy),
                                    None, None, 0, byref(outdata)):
            raise Exception("Failed to decrypt user key key (sic)")
        return string_at(outdata.pbData, outdata.cbData)
    return CryptUnprotectData
CryptUnprotectData = CryptUnprotectData()

DEVICE_KEY_PATH = r'Software\Adobe\Adept\Device'

def GetMasterKey(): 
    root = GetSystemDirectory().split('\\')[0] + '\\'
    serial = GetVolumeSerialNumber(root)
    vendor = cpuid0()
    signature = struct.pack('>I', cpuid1())[1:]
    try: 
        regkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, DEVICE_KEY_PATH)
        device = winreg.QueryValueEx(regkey, 'key')[0]

        # ADE puts an "username" attribute into that key which was unused
        # in previous versions of this script. This means that this key 
        # retrieval script would break / not work if the user had ever
        # changed their Windows account user name after installing ADE.
        # By reading the "username" registry entry if available we won't
        # have that problem anymore.

        try: 
            user = winreg.QueryValueEx(regkey, 'username')[0].encode('utf-16-le')[::2]
            # Yes, this actually only uses the lowest byte of each character.
        except:
            # This value should always be available, but just in case
            # it's not, use the old implementation.
            user = GetUserName()

    except WindowsError: 
        return None

    entropy = struct.pack('>I12s3s13s', serial, vendor, signature, user)
    try: 
        keykey = CryptUnprotectData(device, entropy)
    except Exception: 
        # There was an exception, so this thing was unable to decrypt
        # the key. Maybe this is due to the new user name handling, so
        # let's retry with the old code. 
        user = GetUserName()
        entropy = struct.pack('>I12s3s13s', serial, vendor, signature, user)
        keykey = CryptUnprotectData(device, entropy)

    return keykey