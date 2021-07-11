# Copyright (c) 2016-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for SSH packet encoding and decoding"""

import codecs
import unittest

from asyncssh.packet import Byte, Boolean, UInt32, UInt64, String, MPInt
from asyncssh.packet import NameList, PacketDecodeError, SSHPacket


class _TestPacket(unittest.TestCase):
    """Unit tests for SSH packet module"""

    tests = [
        (Byte, SSHPacket.get_byte, [
            (0,                               '00'),
            (127,                             '7f'),
            (128,                             '80'),
            (255,                             'ff')
        ]),

        (Boolean, SSHPacket.get_boolean, [
            (False,                           '00'),
            (True,                            '01')
        ]),

        (UInt32, SSHPacket.get_uint32, [
            (0,                               '00000000'),
            (256,                             '00000100'),
            (0x12345678,                      '12345678'),
            (0x7fffffff,                      '7fffffff'),
            (0x80000000,                      '80000000'),
            (0xffffffff,                      'ffffffff')
        ]),

        (UInt64, SSHPacket.get_uint64, [
            (0,                               '0000000000000000'),
            (256,                             '0000000000000100'),
            (0x123456789abcdef0,              '123456789abcdef0'),
            (0x7fffffffffffffff,              '7fffffffffffffff'),
            (0x8000000000000000,              '8000000000000000'),
            (0xffffffffffffffff,              'ffffffffffffffff')
        ]),

        (String, SSHPacket.get_string, [
            (b'',                             '00000000'),
            (b'foo',                          '00000003666f6f'),
            (1024*b'\xff',                    '00000400' + 1024*'ff')
        ]),

        (MPInt, SSHPacket.get_mpint, [
            (0,                               '00000000'),
            (1,                               '0000000101'),
            (127,                             '000000017f'),
            (128,                             '000000020080'),
            (32767,                           '000000027fff'),
            (32768,                           '00000003008000'),
            (0x123456789abcdef01234,          '0000000a123456789abcdef01234'),
            (-1,                              '00000001ff'),
            (-128,                            '0000000180'),
            (-129,                            '00000002ff7f'),
            (-32768,                          '000000028000'),
            (-32769,                          '00000003ff7fff'),
            (-0xdeadbeef,                     '00000005ff21524111')
        ]),

        (NameList, SSHPacket.get_namelist, [
            ([],                              '00000000'),
            ([b'foo'],                        '00000003666f6f'),
            ([b'foo', b'bar'],                '00000007666f6f2c626172')
        ])
    ]

    encode_errors = [
        (Byte, -1,                            ValueError),
        (Byte, 256,                           ValueError),
        (Byte, 'a',                           TypeError),

        (UInt32, None,                        AttributeError),
        (UInt32, -1,                          OverflowError),
        (UInt32, 0x100000000,                 OverflowError),

        (UInt64, None,                        AttributeError),
        (UInt64, -1,                          OverflowError),
        (UInt64, 0x10000000000000000,         OverflowError),

        (String, None,                        TypeError),
        (String, True,                        TypeError),
        (String, 0,                           TypeError),

        (MPInt, None,                         AttributeError),
        (MPInt, '',                           AttributeError),
        (MPInt, [],                           AttributeError),

        (NameList, None,                      TypeError),
        (NameList, 'xxx',                     TypeError)
    ]

    decode_errors = [
        (SSHPacket.get_byte,                  ''),
        (SSHPacket.get_byte,                  '1234'),
        (SSHPacket.get_boolean,               ''),
        (SSHPacket.get_boolean,               '1234'),
        (SSHPacket.get_uint32,                '123456'),
        (SSHPacket.get_uint32,                '1234567890'),
        (SSHPacket.get_uint64,                '12345678'),
        (SSHPacket.get_uint64,                '123456789abcdef012'),
        (SSHPacket.get_string,                '123456'),
        (SSHPacket.get_string,                '12345678'),
        (SSHPacket.get_string,                '000000011234')
    ]

    def test_packet(self):
        """Unit test SSH packet module"""

        for encode, decode, values in self.tests:
            for value, data in values:
                data = codecs.decode(data, 'hex')

                with self.subTest(msg='encode', value=value):
                    self.assertEqual(encode(value), data)

                with self.subTest(msg='decode', data=data):
                    packet = SSHPacket(data)
                    decoded_value = decode(packet)
                    packet.check_end()
                    self.assertEqual(decoded_value, value)
                    self.assertEqual(packet.get_consumed_payload(), data)
                    self.assertEqual(packet.get_remaining_payload(), b'')

        for encode, value, exc in self.encode_errors:
            with self.subTest(msg='encode error', encode=encode, value=value):
                with self.assertRaises(exc):
                    encode(value)

        for decode, data in self.decode_errors:
            with self.subTest(msg='decode error', data=data):
                with self.assertRaises(PacketDecodeError):
                    packet = SSHPacket(codecs.decode(data, 'hex'))
                    decode(packet)
                    packet.check_end()

    def test_unicode(self):
        """Unit test encoding of UTF-8 string"""

        self.assertEqual(String('\u2000'), b'\x00\x00\x00\x03\xe2\x80\x80')
