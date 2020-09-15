#!/usr/bin/python
"""
This script is similar in output to parse.c from the radiotap-library
project and can be used to test the python library against its test
cases.
"""

import radiotap as r
import sys

# iterbytes is adapted from the six module
# Copyright (c) 2010-2020 Benjamin Peterson
# https://github.com/benjaminp/six/
if sys.version_info[0] == 3:
    iterbytes = iter
else:
    import functools
    import itertools
    iterbytes = functools.partial(itertools.imap, ord)

fields_to_print = {
    'TSFT': [ 'TSFT', lambda x : x ],
    'flags': [ 'flags', lambda x : '%x' % x ],
    'rate': [ 'rate', lambda x : '%f' % x ],
    'rx_flags': [ 'RX flags', lambda x: '%0.4x' % x ]
}

def datastr(data, sep):
    return sep.join('%.2x' % k for k in iterbytes(data))

def print_vendor(row):
    """ Print vendor lines that match what parse.c does
    """
    data = row['data']
    oui = row['oui']

    if ((row['present'] & (1 << 0)) or
        (row['present'] & (1 << 52))):

        bit = 0 if (row['present'] & (1 << 0)) else 52
        print('\t%s-%.2x|%d: %s' % (
             datastr(oui, ':'), row['subns'], bit, datastr(data, '/')))
    elif row['subns'] != 0:
        print('\tvendor NS (%s:%d, %d bytes)\n\t\t%s' % (
             datastr(oui, '-'), row['subns'], len(data),
             datastr(data, ' ')))

def parse_file(fn):
    pkt = open(fn, 'rb').read()

    while len(pkt):
        off, radiotap = r.radiotap_parse(pkt, valuelist=True)
        for row in radiotap:
            if 'oui' in row:
                print_vendor(row)
            for k,v in row.items():
                if k in fields_to_print:
                    lbl, fmt = fields_to_print[k]
                    print('\t%s: %s' % (lbl, fmt(v)))
        pkt = pkt[off:]

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s [file]" % sys.argv[0])
        sys.exit(1)

    parse_file(sys.argv[1])

