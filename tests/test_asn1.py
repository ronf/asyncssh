# Copyright (c) 2015-2021 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    that license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for ASN.1 encoding and decoding"""

import codecs
import unittest

from asyncssh.asn1 import der_encode, der_decode
from asyncssh.asn1 import ASN1EncodeError, ASN1DecodeError
from asyncssh.asn1 import BitString, IA5String, ObjectIdentifier
from asyncssh.asn1 import RawDERObject, TaggedDERObject, PRIVATE

class _TestASN1(unittest.TestCase):
    """Unit tests for ASN.1 module"""

    tests = [
        (None,                                '0500'),

        (False,                               '010100'),
        (True,                                '0101ff'),

        (0,                                   '020100'),
        (127,                                 '02017f'),
        (128,                                 '02020080'),
        (256,                                 '02020100'),
        (-128,                                '020180'),
        (-129,                                '0202ff7f'),
        (-256,                                '0202ff00'),

        (b'',                                 '0400'),
        (b'\0',                               '040100'),
        (b'abc',                              '0403616263'),
        (127*b'\0',                           '047f' + 127*'00'),
        (128*b'\0',                           '048180' + 128*'00'),

        ('',                                  '0c00'),
        ('\0',                                '0c0100'),
        ('abc',                               '0c03616263'),

        ((),                                  '3000'),
        ((1,),                                '3003020101'),
        ((1, 2),                              '3006020101020102'),

        (frozenset(),                         '3100'),
        (frozenset({1}),                      '3103020101'),
        (frozenset({1, 2}),                   '3106020101020102'),
        (frozenset({-128, 127}),              '310602017f020180'),

        (BitString(b''),                      '030100'),
        (BitString(b'\0', 7),                 '03020700'),
        (BitString(b'\x80', 7),               '03020780'),
        (BitString(b'\x80', named=True),      '03020780'),
        (BitString(b'\x81', named=True),      '03020081'),
        (BitString(b'\x81\x00', named=True),  '03020081'),
        (BitString(b'\x80', 6),               '03020680'),
        (BitString(b'\x80'),                  '03020080'),
        (BitString(b'\x80\x00', 7),           '0303078000'),
        (BitString(''),                       '030100'),
        (BitString('0'),                      '03020700'),
        (BitString('1'),                      '03020780'),
        (BitString('10'),                     '03020680'),
        (BitString('10000000'),               '03020080'),
        (BitString('10000001'),               '03020081'),
        (BitString('100000000'),              '0303078000'),

        (IA5String(b''),                      '1600'),
        (IA5String(b'\0'),                    '160100'),
        (IA5String(b'abc'),                   '1603616263'),

        (ObjectIdentifier('0.0'),             '060100'),
        (ObjectIdentifier('1.2'),             '06012a'),
        (ObjectIdentifier('1.2.840'),         '06032a8648'),
        (ObjectIdentifier('2.5'),             '060155'),
        (ObjectIdentifier('2.40'),            '060178'),

        (TaggedDERObject(0, None),            'a0020500'),
        (TaggedDERObject(1, None),            'a1020500'),
        (TaggedDERObject(32, None),           'bf20020500'),
        (TaggedDERObject(128, None),          'bf8100020500'),
        (TaggedDERObject(0, None, PRIVATE),   'e0020500'),

        (RawDERObject(0, b'', PRIVATE),       'c000')
    ]

    encode_errors = [
        (range, [1]),                         # Unsupported type

        (BitString, [b'', 1]),                # Bit count with empty value
        (BitString, [b'', -1]),               # Invalid unused bit count
        (BitString, [b'', 8]),                # Invalid unused bit count
        (BitString, [b'0c0', 7]),             # Unused bits not zero
        (BitString, ['', 1]),                 # Unused bits with string
        (BitString, [0]),                     # Invalid type

        (ObjectIdentifier, ['']),             # Too few components
        (ObjectIdentifier, ['1']),            # Too few components
        (ObjectIdentifier, ['-1.1']),         # First component out of range
        (ObjectIdentifier, ['3.1']),          # First component out of range
        (ObjectIdentifier, ['0.-1']),         # Second component out of range
        (ObjectIdentifier, ['0.40']),         # Second component out of range
        (ObjectIdentifier, ['1.-1']),         # Second component out of range
        (ObjectIdentifier, ['1.40']),         # Second component out of range
        (ObjectIdentifier, ['1.1.-1']),       # Later component out of range

        (TaggedDERObject, [0, None, 99]),     # Invalid ASN.1 class

        (RawDERObject, [0, None, 99]),        # Invalid ASN.1 class
    ]

    decode_errors = [
        '',                                   # Incomplete data
        '01',                                 # Incomplete data
        '0101',                               # Incomplete data
        '1f00',                               # Incomplete data
        '1f8000',                             # Incomplete data
        '1f0001',                             # Incomplete data

        '1f80',                               # Incomplete tag

        '0180',                               # Indefinite length

        '050001',                             # Unexpected bytes at end

        '2500',                               # Constructed null
        '050100',                             # Null with content

        '2100',                               # Constructed boolean
        '010102',                             # Boolean value not 0x00/0xff

        '2200',                               # Constructed integer

        '2400',                               # Constructed octet string

        '2c00',                               # Constructed UTF-8 string

        '1000',                               # Non-constructed sequence

        '1100',                               # Non-constructed set

        '2300',                               # Constructed bit string
        '03020800',                           # Invalid unused bit count

        '3600',                               # Constructed IA5 string

        '2600',                               # Constructed object identifier
        '0600',                               # Empty object identifier
        '06020080',                           # Invalid component
        '06020081'                            # Incomplete component
    ]

    def test_asn1(self):
        """Unit test ASN.1 module"""

        for value, data in self.tests:
            data = codecs.decode(data, 'hex')

            with self.subTest(msg='encode', value=value):
                self.assertEqual(der_encode(value), data)

            with self.subTest(msg='decode', data=data):
                decoded_value = der_decode(data)
                self.assertEqual(decoded_value, value)
                self.assertEqual(hash(decoded_value), hash(value))
                self.assertEqual(repr(decoded_value), repr(value))
                self.assertEqual(str(decoded_value), str(value))

        for cls, args in self.encode_errors:
            with self.subTest(msg='encode error', cls=cls.__name__, args=args):
                with self.assertRaises(ASN1EncodeError):
                    der_encode(cls(*args))

        for data in self.decode_errors:
            with self.subTest(msg='decode error', data=data):
                with self.assertRaises(ASN1DecodeError):
                    der_decode(codecs.decode(data, 'hex'))
