#!/usr/bin/env python

import re
import sys

modif = re.compile(r'^\(\?([ism]+):(.*)\)$')

def convert(reg):
    m = modif.search(reg)
    if m:
        m = m.groups()
        return '/{}/{}'.format(m[1], m[0])
    return '/{}/'.format(reg)


with open(sys.argv[1]) as f:
    for l in f:
        rid, reg = l[:-1].split('\t')
        reg = convert(reg)
        print("{}\t{}".format(rid, reg))
