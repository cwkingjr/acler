#!/usr/bin/env python

import csv
import optparse
import os
import sys

counter = 1

""" process commandline options """
usage = """usage: ./%prog [options]
use -h for help / option descriptions 
example: ./%prog -i /path/to/my/no-integer-csv-file.csv
"""
parser = optparse.OptionParser(usage)
parser.add_option("-i", "--in-file", dest="infile", help="""CSV file to prepend tracking line number integers to.""")
(options, args) = parser.parse_args()

if not options.infile:
    print("Input file option [-i] required. See help using -h")
    sys.exit(1)

# get the infile name without extension
myname = os.path.splitext(os.path.basename(options.infile))[0] 
mypath = os.path.dirname(options.infile)
csvoutfilename = "%s-with-integers.csv" % myname
csvoutfile = "%s/%s" % (mypath, csvoutfilename)

# load list with input csv info
csvin = list()
with open(options.infile, 'rb') as rf:
    reader = csv.reader(rf)
    for row in reader:
        row = [counter] + row
        csvin.append(row)
        counter += 1
   
with open(csvoutfile, 'wb') as wf:
    writer = csv.writer(wf)
    for row in csvin:
        writer.writerow(row)
