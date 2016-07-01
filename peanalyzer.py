import os.path
import textwrap
import time
import struct
from collections import namedtuple
from pprint import pprint

# Definitions
def ByteToHex(byteStr):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def strfhex(a) :
    # return ByteToHex(a)
    return ByteToHex(str(a))

# Startup Printing
VERSION = '0.0.0.3'
print('PE Analyzer [Version ' + VERSION + ']')
print('2016 by mkpoli.')
print()

# Input file
while True:
    fname = input('Please input the path of the PE file that you want to analyze: ')
    if os.path.isfile(fname) :
        break
    else :
        print('Error: Not a file. Please reinput.')

# Processing
# TODO: wrap text

# Basic File Info
# TODO: Use os.stat
# TODO: import python-magic
TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
fsize = os.path.getsize(fname)
fatime = os.path.getatime(fname)
fmtime = os.path.getmtime(fname)
fctime = os.path.getctime(fname)

print('-- File Information -- ',
'      File Name = ' + fname,
'      File Size = ' + str(fsize) + ' Bytes',
'      Last Access Time = ' + str(fatime) + ', in UTC = ' + time.strftime(TIME_FORMAT, time.gmtime(fatime)) + ', in Local = ' + time.strftime(TIME_FORMAT, time.localtime(fatime)),
'      Last Modify Time = ' + str(fmtime) + ', in UTC = ' + time.strftime(TIME_FORMAT, time.gmtime(fmtime)) + ', in Local = ' + time.strftime(TIME_FORMAT, time.localtime(fmtime)),
'      Last Create Time = '  + str(fctime) + ', in UTC = ' + time.strftime(TIME_FORMAT, time.gmtime(fctime))+ ', in Local = ' + time.strftime(TIME_FORMAT, time.localtime(fctime)),
sep='\n')
print()
# File Stream Processing

signature = [None] * 2
reserved1 = [None] * 4
reserved2 = [None] * 10
with open(fname, "rb") as f:
    content = f.read()
    # print(len(content), len(content[:96]))
    DOSHeader = namedtuple('DOSHeader', 'signature_0 signature_1 lastsize nblocks nreloc hdrsize minalloc maxalloc ss sp checksum ip cs relocps noverlay reserved1_0 reserved1_1 reserved1_2 reserved1_3 oem_id oem_info reserved2_0 reserved2_1 reserved2_2 reserved2_3 reserved2_4 reserved2_5 reserved2_6 reserved2_7 reserved2_8 reserved2_9 e_lfanew')
    dosheader = DOSHeader._make(struct.unpack("cchhhhhhPPhPPhhhhhhhhhhhhhhhhhhl", content[:96]))
    (signature[0], signature[1], lastsize, nblocks, nreloc, hdrsize, minalloc, maxalloc, ss, sp, checksum, ip, cs, relocps, noverlay, reserved1[0], reserved1[1], reserved1[2], reserved1[3], oem_id, oem_info, reserved2[0], reserved2[1], reserved2[2], reserved2[3], reserved2[4], reserved2[5], reserved2[6], reserved2[7], reserved2[8], reserved2[9], e_lfanew) = struct.unpack("cchhhhhhPPhPPhhhhhhhhhhhhhhhhhhl", content[:96]) # DOS Header
    pprint(dosheader)

# print(repr(globals()))
# print(str(loaded))
# print(repr(loaded))

# with open(fname, "rb") as f:
#     magicn = f.read(2)
#     hasMZ = (magicn == b'MZ')
#     if not hasMZ :
#         print('-- PE Information -- ',
#         '     Has Valid Magic Number "MZ" = ' + str(hasMZ),
#         '',
#         'This is NOT a PE File. Stopping Processing.',
#         sep='\n')
#         exit()
#     # magicn = magicn
#     lasesize = f.read(2)
#     nblocks = f.read(2)
#     nreloc = f.read(2)
#     hdrsize = f.read(2)
#     minalloc = f.read(2)
#     maxalloc = f.read(2)
#     ss = f.read(2)
#     sp = f.read(2)
#     checksum = f.read(2)
#     ip = f.read(2)
#     cs = f.read(2)
#     relocps = f.read(2)
#     noverlay = f.read(2)
#     reserved1 = f.read(8)
#     oem_id = f.read(2)
#     oem_info = f.read(2)
#     reserved2 = f.read(20) # sum = 60 = 3c
#     pepointer = f.read(4)
#     print(repr(globals()))

#     print('-- PE Information -- ',
#     '     Has Valid Magic Number "MZ" = ' + str(hasMZ),
#     '     PE Pointer = ' + strfhex(pepointer),
#     sep='\n')
#     print()
#     print('-- DOS Header --',
#     '    signature[2] = ' + strfhex(magicn),
#     '    lasesize = ' + strfhex(lasesize),
#     '    nblocks = ' + strfhex(nblocks),
#     '    nreloc = ' + strfhex(nreloc),
#     '    hdrsize = ' + strfhex(hdrsize),
#     sep='\n')