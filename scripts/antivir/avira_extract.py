#!/usr/bin/env python3

import cgi
import io
import os.path
import struct
import sys
import zipfile


def extract_zip(stream):
    # extract the name="file_eml" part of a multi part form
    pdict = {'boundary': b'--MULTI-PARTS-FORM-DATA-BOUNDARY'}
    parts = cgi.parse_multipart(stream, pdict)
    return parts['file_eml'][0]


def unzip(data):
    # creates a fake file like object from bytes
    f = io.BytesIO(data)
    with zipfile.ZipFile(f) as myzip:
        # get first file in zip
        f1 = myzip.filelist[0].filename
        with myzip.open(f1) as qua:
            return qua.read()


def read_str(data, start):
    """ Read UTF-8 string """
    s = bytearray()
    while data[start]:
        s.append(data[start])
        start += 1
    return s.decode('utf-8')


def read_str_le(data, start):
    """ Read UTF-16 little endian string """
    s = bytearray()
    while data[start] or data[start + 1]:
        s.extend(data[start:start + 2])
        start += 2
    return s.decode('utf-16-le')


def decode_qua(data):
    # check that data is a valid Qua file
    assert data[0:11] == b'AntiVir Qua'
    # extract usefull info from header
    sample_pos = struct.unpack('<I', data[16:20])[0]
    signature = read_str(data, 0x9c)
    path = read_str_le(data, 0xdc)
    info_start = 0xdc + len(path) * 2 + 2
    if path.startswith('\\\\.\\'):
        path = path[4:]
    info = read_str_le(data, info_start)
    return {'signature': signature,
            'path': path,
            'info': info,
            'data': data[sample_pos:]}


def xor(data, key):
    return bytes(b ^ key for b in data)


def main():
    """ Program entry point """
    if len(sys.argv) not in (2, 3) or not os.path.isfile(sys.argv[1]):
        print(f'Usage: {sys.argv[0]} multi-part-form-file', file=sys.stderr)
        sys.exit(1)
    prefix = sys.argv[2] + '_' if len(sys.argv) == 3 else ''

    # extract zip from multi-part form
    with open(sys.argv[1], 'rb') as f:
        data = extract_zip(f)

    # extract QUA file from zip
    qua = unzip(data)

    # extract and decode info from QUA file
    decoded = decode_qua(qua)
    filename = decoded['path'].split('\\')[-1]
    filename = prefix + filename

    # write info file
    with open(f'{filename}.info', 'w', encoding='utf-8') as f:
        print('signature:', decoded['signature'], file=f)
        print('path:', decoded['path'], file=f)
        print('info:', decoded['info'], file=f)

    # write sample
    with open(filename, 'wb') as f:
        f.write(xor(decoded['data'], 0xaa))


if __name__ == '__main__':
    main()
