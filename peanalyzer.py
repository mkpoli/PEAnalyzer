import os.path

# Startup Printing
VERSION = '0.0.0.1'
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
        
# Basic File Info
print('-- File Information -- ',
'      File Name = ' + fname,
'      File Size = ' + str(os.path.getsize(fname)) + ' Bytes'
, sep='\n')