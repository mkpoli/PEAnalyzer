import os.path
import textwrap
import time

# Startup Printing
VERSION = '0.0.0.2'
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

# File Stream Processing
with open(fname, "rb") as f:
    magicn = f.read(2)
    hasMZ = (magicn == b'MZ')
    if not hasMZ :
        print('-- PE Information -- ',
        '     Has Valid Magic Number "MZ" = ' + str(hasMZ),
        '',
        'This is NOT a PE File. Stopping Processing.',
        sep='\n')
        exit()
    f.read(0x3A)
    pepointer = f.read(1)
    print('-- PE Information -- ',
    '     Has Valid Magic Number "MZ" = ' + str(hasMZ),
    '     PE Pointer = ' + str(pepointer),
    sep='\n')
