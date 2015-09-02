# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
# All rights reserved.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v1.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-v10.html
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Unit tests for SASL string preparation"""

import unittest

from asyncssh.saslprep import saslprep, SASLPrepError

class _TestSASLPrep(unittest.TestCase):
    """Unit tests for saslprep module"""

    def test_nonstring(self):
        """Test passing a non-string value"""

        with self.assertRaises(TypeError):
            saslprep(b'xxx')

    def test_unassigned(self):
        """Test passing strings with unassigned code points"""

        for s in ('\u0221', '\u038b', '\u0510', '\u070e', '\u0900', '\u0a00'):
            with self.assertRaises(SASLPrepError, msg='U+%08x' % ord(s)):
                saslprep('abc' + s + 'def')

    def test_map_to_nothing(self):
        """Test passing strings with characters that map to nothing"""

        for s in ('\u00ad', '\u034f', '\u1806', '\u200c', '\u2060', '\ufe00'):
            self.assertEqual(saslprep('abc' + s + 'def'), 'abcdef',
                             msg='U+%08x' % ord(s))

    def test_map_to_whitespace(self):
        """Test passing strings with characters that map to whitespace"""
        for s in ('\u00a0', '\u1680', '\u2000', '\u202f', '\u205f', '\u3000'):
            self.assertEqual(saslprep('abc' + s + 'def'), 'abc def',
                             msg='U+%08x' % ord(s))

    def test_normalization(self):
        """Test Unicode normalization form KC conversions"""
        for (s, n) in (('\u00aa', 'a'), ('\u2168', 'IX')):
            self.assertEqual(saslprep('abc' + s + 'def'), 'abc' + n + 'def',
                             msg='U+%08x' % ord(s))

    def test_prohibited(self):
        """Test passing strings with prohibited characters"""
        for s in ('\u0000', '\u007f', '\u0080', '\u06dd', '\u180e', '\u200e',
                  '\u2028', '\u202a', '\u206a', '\u2ff0', '\u2ffb', '\ud800',
                  '\udfff', '\ue000', '\ufdd0', '\ufef9', '\ufffc', '\uffff',
                  '\U0001d173', '\U000E0001', '\U00100000', '\U0010fffd'):
            with self.assertRaises(SASLPrepError, msg='U+%08x' % ord(s)):
                saslprep('abc' + s + 'def')

    def test_bidi(self):
        """Test passing strings with bidirectional characters"""

        for s in ('\u05be\u05c0\u05c3\u05d0', # RorAL only
                  'abc\u00c0\u00c1\u00c2',    # L only
                  '\u0627\u0031\u0628'):      # Mix of RorAL and other
            self.assertEqual(saslprep(s), s)

        with self.assertRaises(SASLPrepError):
            saslprep('abc\u05be\u05c0\u05c3') # Mix of RorAL and L

        with self.assertRaises(SASLPrepError):
            saslprep('\u0627\u0031')          # RorAL not at both start & end
