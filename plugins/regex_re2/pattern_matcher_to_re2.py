#!/usr/bin/env python3

# Converts the regex_config.txt file from the regex_pattern_matcher T3 plugin
# to the format supported by the RE2 regex plugin.

import fileinput, re, sys

pattern1 = re.compile(r'^#(\d+);(.+)$')
pattern2 = re.compile(r'^compile:\s*([a-fA-F0-9]+)$')
pattern3 = re.compile(r'^(prev|dump|flowdump|study|write):\s*([a-fA-F0-9]+)$')

modifiersMap = {
    0x00000001: 'i',
    0x00000002: 'm',
    0x00000004: 's',
    0x00000200: 'U',
    # The other flags are either not supported by RE2 or supported
    # only per set of regexes and not per individual regex in a set.
}

regex = None
regex_id = None
flags = ""
ignore = False

def outputRule():
    global regex, regex_id, flags, ignore
    if regex and not ignore:
        if flags:
            print('{}\t(?{}){}'.format(regex_id, flags, regex))
        else:
            print('{}\t{}'.format(regex_id, regex))

# print header
print('%This is the config file for the regex_re2 plugin')
print('%regexID\tregex')

for l in fileinput.input():
    # skip comments and empty lines
    if l.startswith('//') or len(l.strip()) == 0:
        continue

    # parse line containing the regex
    m = pattern1.match(l)
    if m:
        # check that the regex has the right format
        if len(m.groups()) != 2:
            print('Invalid regex format: {}'.format(l), file=sys.stderr)
            ignore = True # ignore the compile flags, dump flags, ... until next regex
            continue
        # print previous regex
        outputRule()
        # reset flags and ignore status
        flags = ""
        ignore = False
        # extract new regex and regex_id
        regex_id, regex = m.groups()
        continue

    # parse compile flags
    m = pattern2.match(l)
    if m and len(m.groups()) == 1:
        comp = int(m.groups()[0], 16)
        for mask in modifiersMap:
            if mask & comp:
                flags += modifiersMap[mask]
        continue

    # ignore all other directives
    if pattern3.match(l):
        continue

    # unknown directive
    print('Unknown directive in regex config file: {}'.format(l), file=sys.stderr)

# print last rule
outputRule()
