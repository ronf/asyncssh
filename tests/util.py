# Copyright (c) 2015-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""Utility functions for unit tests"""

import asyncio
import binascii
import functools
import os
import platform
import subprocess
import tempfile
import unittest

# pylint: disable=unused-import

try:
    import bcrypt
    bcrypt_available = hasattr(bcrypt, 'kdf')
except ImportError: # pragma: no cover
    bcrypt_available = False

try:
    import libnacl
    libnacl_available = True
except (ImportError, OSError, AttributeError): # pragma: no cover
    libnacl_available = False

# pylint: enable=unused-import

from asyncssh.constants import DISC_CONNECTION_LOST
from asyncssh.misc import DisconnectError, SignalReceived
from asyncssh.packet import String, UInt32, UInt64


if platform.python_version_tuple() >= ('3', '4', '4'):
    create_task = asyncio.ensure_future
else: # pragma: no cover
    create_task = asyncio.async


def asynctest(func):
    """Decorator for async tests, for use with AsyncTestCase"""

    @functools.wraps(func)
    def async_wrapper(self, *args, **kwargs):
        """Run a function as a coroutine and wait for it to finish"""

        wrapped_func = asyncio.coroutine(func)(self, *args, **kwargs)
        return self.loop.run_until_complete(wrapped_func)

    return async_wrapper


def asynctest35(func):
    """Decorator for Python 3.5 async tests, for use with AsyncTestCase"""

    @functools.wraps(func)
    def async_wrapper(self, *args, **kwargs):
        """Run a function as a coroutine and wait for it to finish"""

        wrapped_func = func(self, *args, **kwargs)
        return self.loop.run_until_complete(wrapped_func)

    return async_wrapper


@asyncio.coroutine
def echo(stdin, stdout, stderr=None):
    """Echo data from stdin back to stdout and stderr (if open)"""

    try:
        while not stdin.at_eof():
            data = yield from stdin.read(65536)

            if data:
                stdout.write(data)

                if stderr:
                    stderr.write(data)

        yield from stdout.drain()

        if stderr:
            yield from stderr.drain()

        stdout.write_eof()
    except SignalReceived as exc:
        if exc.signal == 'ABRT':
            raise DisconnectError(DISC_CONNECTION_LOST, 'Abort')
        else:
            stdin.channel.exit_with_signal(exc.signal)
    except OSError:
        pass

    stdout.close()


def _encode_options(options):
    """Encode SSH certificate critical options and extensions"""

    return b''.join((String(k) + String(v) for k, v in options.items()))


def make_certificate(cert_version, cert_type, key, signing_key, principals,
                     key_id='name', valid_after=0,
                     valid_before=0xffffffffffffffff, options=None,
                     extensions=None, bad_signature=False):
    """Construct an SSH certificate"""

    keydata = key.encode_ssh_public()
    principals = b''.join((String(p) for p in principals))
    options = _encode_options(options) if options else b''
    extensions = _encode_options(extensions) if extensions else b''
    signing_keydata = b''.join((String(signing_key.algorithm),
                                signing_key.encode_ssh_public()))

    data = b''.join((String(cert_version), String(os.urandom(32)), keydata,
                     UInt64(0), UInt32(cert_type), String(key_id),
                     String(principals), UInt64(valid_after),
                     UInt64(valid_before), String(options),
                     String(extensions), String(''), String(signing_keydata)))

    if bad_signature:
        data += String('')
    else:
        data += String(signing_key.sign(data, signing_key.algorithm))

    return b''.join((cert_version.encode('ascii'), b' ',
                     binascii.b2a_base64(data)))


def run(cmd):
    """Run a shell commands and return the output"""

    try:
        return subprocess.check_output(cmd, shell=True,
                                       stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc: # pragma: no cover
        print(exc.output.decode())
        raise


class ConnectionStub:
    """Stub class used to replace an SSHConnection object"""

    def __init__(self, peer, server):
        self._peer = peer
        self._server = server

        if peer:
            self._packet_queue = asyncio.queues.Queue()
            self._queue_task = create_task(self._process_packets())
        else:
            self._packet_queue = None
            self._queue_task = None

    def is_client(self):
        """Return if this is a client connection"""

        return not self._server

    def is_server(self):
        """Return if this is a server connection"""

        return self._server

    def get_peer(self):
        """Return the peer of this connection"""

        return self._peer

    @asyncio.coroutine
    def _process_packets(self):
        """Process the queue of incoming packets"""

        while True:
            data = yield from self._packet_queue.get()
            self.process_packet(data)

    def process_packet(self, data):
        """Process an incoming packet"""

        raise NotImplementedError

    def queue_packet(self, *args):
        """Add an incoming packet to the queue"""

        self._packet_queue.put_nowait(b''.join(args))

    def send_packet(self, *args):
        """Send a packet to this connection's peer"""

        if self._peer:
            self._peer.queue_packet(*args)

    def close(self):
        """Close the connection, stopping processing of incoming packets"""

        if self._queue_task:
            # This is a pylint false positive
            # pylint: disable=no-member
            self._queue_task.cancel()
            self._queue_task = None


class TempDirTestCase(unittest.TestCase):
    """Unit test class which operates in a temporary directory"""

    tempdir = None

    @classmethod
    def setUpClass(cls):
        """Create temporary directory and set it as current directory"""

        cls._tempdir = tempfile.TemporaryDirectory()
        os.chdir(cls._tempdir.name)

    @classmethod
    def tearDownClass(cls):
        """Clean up temporary directory"""

        cls._tempdir.cleanup()


class AsyncTestCase(TempDirTestCase):
    """Unit test class which supports tests using asyncio"""

    loop = None

    @classmethod
    def setUpClass(cls):
        """Set up event loop to run async tests and run async class setup"""

        super().setUpClass()

        cls.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls.loop)

        try:
            # pylint: disable=no-member
            cls.loop.run_until_complete(cls.asyncSetUpClass())
        except AttributeError:
            pass

    @classmethod
    def tearDownClass(cls):
        """Run async class teardown and close event loop"""

        try:
            # pylint: disable=no-member
            cls.loop.run_until_complete(cls.asyncTearDownClass())
        except AttributeError:
            pass

        cls.loop.close()

        super().tearDownClass()

    def setUp(self):
        """Run async setup if any"""

        try:
            # pylint: disable=no-member
            self.loop.run_until_complete(self.asyncSetUp())
        except AttributeError:
            pass

    def tearDown(self):
        """Run async teardown if any"""

        try:
            # pylint: disable=no-member
            self.loop.run_until_complete(self.asyncTearDown())
        except AttributeError:
            pass
