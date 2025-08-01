#!/usr/bin/env python3

import os
import struct
import sys

from base64 import b64decode
from binascii import hexlify
from itertools import cycle

STREAM_FILE = os.path.dirname(os.path.abspath(__file__)) + '/avg-cipher.bin'
PATH_PREFIX = 'Original file location: '
SIG_PREFIX = 'Virus name: '
STREAM = None


def decrypt(data):
    """
    Decrypt function for data encrypted with cyphSimpleCode function from aswCmnIS.dll
    Repeating stream cipher using a static array in aswCmIS.dll[291592:296792]
    """
    global STREAM
    if not STREAM:
        with open(STREAM_FILE, 'rb') as f:
            STREAM = f.read()
    plaintext = bytearray()
    for i in range(0, len(data), 0x10000):
        plaintext.extend(bytes((a ^ b) for a, b in zip(data[i:i + 0x10000], cycle(STREAM))))
    return plaintext


def decode_field(data, start):
    t = data[start:start + 4]
    start += 4
    s = struct.unpack('<I', data[start:start + 4])[0]
    start += 4
    field = {'type': t.decode('utf-8'), 'size': s}
    if t in [b'NAME', b'TYPE', b'DESC', b'VIRU', b'SCOO', b'EMAI', b'USID', b'META']:
        field['data'] = data[start:start + s - 2].decode('utf-16-le')
    elif t in [b'GUID', b'UNID']:
        field['data'] = data[start:start + s].decode('utf-8')
    elif t == b'HTYP':
        h_name = data[start:start + s + 4].decode('utf-8')
        start += s + 4
        h_len = struct.unpack('<I', data[start:start + 4])[0]
        start += 4
        h = data[start:start + h_len]
        s += 8 + h_len
        field['data'] = (h_name, h)
    elif t == b'SIZE':
        if s == 4:
            size = struct.unpack('<I', data[start:start + 4])[0]
        elif s == 8:
            size = struct.unpack('<Q', data[start:start + 8])[0]
        else:
            raise RuntimeError(f'Unsupported SIZE field of length {s}')
        field['data'] = size
    else:
        field['data'] = data[start:start + s]
    return field


def decode_meta(data, result):
    length = len(data)
    start = 0
    while start + 8 < length:
        t = data[start:start + 4]
        t, s = struct.unpack('<II', data[start:start + 8])
        start += 8
        if start + s >= length:
            break
        val = data[start:start + s]
        if t == 0:
            result['meta_path'] = val[:-1].decode('utf-8')
        elif t == 0x19:
            result['meta_hash'] = ('SHA256HASH', hexlify(val).decode('utf-8'))
        start += s


def decode_avast(data):
    size = len(data)
    # check header magic
    assert data[0:4] == b'\xa1\xa5\x70\x00'
    start = 4
    result = {}
    # decode file field by field
    while start < size:
        field = decode_field(data, start)
        if field['type'] == 'DATA':
            result['data'] = field['data']
        elif field['type'] == 'SCOO':
            # extract useful info from SCOO field
            lines = field['data'].splitlines()
            for line in lines:
                if line.startswith(PATH_PREFIX):
                    result['path'] = line[len(PATH_PREFIX):]
                elif line.startswith(SIG_PREFIX):
                    result['signature'] = line[len(SIG_PREFIX):]
            result['os'] = lines[-1].strip()
        elif field['type'] == 'TYPE':
            if field['data'] == 'VirusDlgStat':
                result['type'] = 'stat'
            elif field['data'].startswith('Submit'):
                result['type'] = 'submit'
            elif field['data'] == 'HeurSuspicious':
                result['type'] = 'heuristic'
        elif field['type'] == 'NAME':
            result['name'] = field['data']
        elif field['type'] == 'VIRU':
            result['viru'] = field['data']
        elif field['type'] == 'META':
            tmp = b64decode(field['data'].split('|')[1])
            decode_meta(tmp, result)
        elif field['type'] == 'HTYP':
            htype, hval = field['data']
            result['hash'] = (htype, hexlify(hval).decode('utf-8'))
        start += 8 + field['size']
    return result


def main():
    """ Program entry point. """
    if len(sys.argv) not in (2, 3) or not os.path.isfile(sys.argv[1]):
        print(f'Usage: {sys.argv[0]} put-content-file', file=sys.stderr)
        sys.exit(1)
    prefix = sys.argv[2] + '_' if len(sys.argv) == 3 else ''

    # load file content in memory
    with open(sys.argv[1], 'rb') as f:
        data = f.read()

    # decode avast file (also used by AVG)
    decoded = decode_avast(data)
    if 'type' not in decoded:
        sys.exit(1)

    # extract sent sample
    if decoded['type'] == 'submit':
        filename = decoded['path'].split('\\')[-1]
        filename = prefix + filename
        # write info file
        with open(f'{filename}.info', 'w', encoding='utf-8') as f:
            print('signature:', decoded['signature'], file=f)
            print('path:', decoded['path'], file=f)
            print('hash:', '{}:{}'.format(*decoded['hash']), file=f)
            print('os:', decoded['os'], file=f)
        # write sample
        with open(filename, 'wb') as f:
            f.write(decrypt(decoded['data']))

    # no sent sample but info about detected malware
    elif decoded['type'] == 'stat':
        filename = decoded['name'].split('\\')[-1]
        filename = prefix + filename
        with open(f'{filename}.stat', 'w', encoding='utf-8') as f:
            print('signature:', decoded['viru'], file=f)
            print('path:', decoded['name'], file=f)
            print('hash:', '{}:{}'.format(*decoded['hash']), file=f)

    # no sent sample but info about heuristic detection
    elif decoded['type'] == 'heuristic':
        filename = decoded['meta_path'].split('\\')[-1]
        filename = prefix + filename
        with open(f'{filename}.heur', 'w', encoding='utf-8') as f:
            print('signature:', decoded['viru'], file=f)
            print('path:', decoded['meta_path'], file=f)
            print('hash:', '{}:{}'.format(*decoded['meta_hash']), file=f)


if __name__ == '__main__':
    main()
