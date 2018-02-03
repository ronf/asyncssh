# Copyright (c) 2015-2018 by Ron Frederick <ronf@timeheart.net>.
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
import subprocess
import sys
import tempfile
import unittest

from unittest.mock import patch

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

try:
    import uvloop
    uvloop_available = True
except ImportError: # pragma: no cover
    uvloop_available = False

try:
    from asyncssh.crypto import X509Name
    x509_available = True
except ImportError: # pragma: no cover
    x509_available = False

# pylint: enable=unused-import

from asyncssh.constants import DISC_CONNECTION_LOST
from asyncssh.gss import gss_available
from asyncssh.logging import logger
from asyncssh.misc import DisconnectError, SignalReceived, create_task
from asyncssh.packet import Byte, String, UInt32, UInt64


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


def patch_gss(cls):
    """Decorator for patching GSSAPI classes"""

    if not gss_available: # pragma: no cover
        return cls

    if sys.platform == 'win32': # pragma: no cover
        from .sspi_stub import SSPIAuth

        cls = patch('asyncssh.gss_win32.ClientAuth', SSPIAuth)(cls)
        cls = patch('asyncssh.gss_win32.ServerAuth', SSPIAuth)(cls)
    else:
        from .gssapi_stub import Name, Credentials, RequirementFlag
        from .gssapi_stub import SecurityContext

        cls = patch('asyncssh.gss_unix.Name', Name)(cls)
        cls = patch('asyncssh.gss_unix.Credentials', Credentials)(cls)
        cls = patch('asyncssh.gss_unix.RequirementFlag', RequirementFlag)(cls)
        cls = patch('asyncssh.gss_unix.SecurityContext', SecurityContext)(cls)

    return cls


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
            self._queue_task = self.create_task(self._process_packets())
        else:
            self._packet_queue = None
            self._queue_task = None

        self._logger = logger.get_child(context='conn=99')

    @property
    def logger(self):
        """A logger associated with this connection"""

        return self._logger

    @asyncio.coroutine
    def _run_task(self, coro):
        """Run an asynchronous task"""

        # pylint: disable=broad-except
        try:
            yield from coro
        except Exception as exc:
            if self._peer: # pragma: no branch
                self.queue_packet(exc)

            self.connection_lost(exc)

    def create_task(self, coro):
        """Create an asynchronous task"""

        return create_task(self._run_task(coro))

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

            if data is None or isinstance(data, Exception):
                self._queue_task = None
                self.connection_lost(data)
                break

            self.process_packet(data)

    def connection_lost(self, exc):
        """Handle the closing of a connection"""

        raise NotImplementedError

    def process_packet(self, data):
        """Process an incoming packet"""

        raise NotImplementedError

    def queue_packet(self, data):
        """Add an incoming packet to the queue"""

        self._packet_queue.put_nowait(data)

    def send_packet(self, pkttype, *args, **kwargs):
        """Send a packet to this connection's peer"""

        # pylint: disable=unused-argument

        if self._peer:
            self._peer.queue_packet(Byte(pkttype) + b''.join(args))

    def close(self):
        """Close the connection, stopping processing of incoming packets"""

        if self._peer:
            self._peer.queue_packet(None)
            self._peer = None

        if self._queue_task:
            self.queue_packet(None)
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

        os.chdir('..')
        cls._tempdir.cleanup()


class AsyncTestCase(TempDirTestCase):
    """Unit test class which supports tests using asyncio"""

    loop = None

    @classmethod
    def setUpClass(cls):
        """Set up event loop to run async tests and run async class setup"""

        super().setUpClass()

        if uvloop_available and os.environ.get('USE_UVLOOP'): # pragma: no cover
            cls.loop = uvloop.new_event_loop()
        else:
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
