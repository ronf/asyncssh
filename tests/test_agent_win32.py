# Copyright (c) 2026 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Unit tests for AsyncSSH ssh-agent client on Windows"""

# These tests exercise internals of agent_win32 directly
# pylint: disable=protected-access

import asyncio
import errno
import io
import os
import sys
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import asyncssh
from asyncssh import agent_win32
from asyncssh.agent import SSH_AGENTC_REQUEST_IDENTITIES
from asyncssh.agent import SSH_AGENT_IDENTITIES_ANSWER
from asyncssh.crypto import ed25519_available
from asyncssh.packet import Byte, String, UInt32

from .util import AsyncTestCase, asynctest, get_test_key

if sys.platform == 'win32': # pragma: cover only win32
    # pylint: disable=import-error
    import mmapfile
    import win32api
    import win32con
    import win32gui


_WM_COPYDATA = 0x004a


class _Win32uiError(Exception):
    """Stub for win32ui.error"""


class _MmapfileError(Exception):
    """Stub for mmapfile.error"""


class _MapFile:
    """Stub for a pywin32 mmapfile object backed by a bytearray"""

    def __init__(self, registry, size):
        self._registry = registry
        self._buf = bytearray(size)
        self._pos = 0
        self.closed = False

    def seek(self, pos):
        """Set the current position in the mapping"""

        self._pos = pos

    def read(self, n):
        """Read up to n bytes from the mapping"""

        data = bytes(self._buf[self._pos:self._pos+n])
        self._pos += len(data)
        return data

    def write(self, data):
        """Write data to the mapping, failing if it would overflow"""

        end = self._pos + len(data)

        if end > len(self._buf):
            raise ValueError('data out of range')

        self._buf[self._pos:end] = data
        self._pos = end

    def close(self):
        """Close the mapping"""

        self.closed = True


class _PageantWindow:
    """Stub for the Pageant window, which answers WM_COPYDATA requests"""

    def __init__(self, mappings, response, send_result):
        self._mappings = mappings
        self._response = response
        self._send_result = send_result
        self.requests = []

    def SendMessage(self, msg, wparam, cds): # pylint: disable=invalid-name
        """Process an agent request in the named shared memory mapping"""

        assert msg == _WM_COPYDATA
        assert wparam == 0
        assert cds.dwData == agent_win32._AGENT_COPYDATA_ID

        mapname = cds.lpData.decode()
        assert cds.cbData == len(mapname) + 1

        mapfile = self._mappings[mapname]

        mapfile.seek(0)
        reqlen = int.from_bytes(mapfile.read(4), 'big')
        self.requests.append(mapfile.read(reqlen))

        mapfile.seek(0)
        mapfile.write(String(self._response))

        return self._send_result


class _StubPageant:
    """Patch agent_win32 to use stub pywin32 modules and a stub Pageant"""

    def __init__(self, response=b'', *, window_present=True,
                 send_result=1, mmap_fails=False):
        self.mappings = {}
        self.window = _PageantWindow(self.mappings, response, send_result)
        self.window_present = window_present
        self._mmap_fails = mmap_fails
        self._patchers = []

    def _find_window(self, class_name, window_name):
        """Return the stub Pageant window if it is present"""

        assert class_name == window_name == agent_win32._AGENT_NAME

        if self.window_present:
            return self.window
        else:
            raise _Win32uiError('Window not found')

    def _mmapfile(self, file, name, size, offset, nbytes):
        """Create a stub shared memory mapping"""

        # pylint: disable=too-many-arguments

        assert file == ''
        assert (offset, nbytes) == (0, 0)

        if self._mmap_fails:
            raise _MmapfileError('Mapping failed')

        mapfile = _MapFile(self.mappings, size)
        self.mappings[name] = mapfile
        return mapfile

    def __enter__(self):
        modules = {
            '_pywin32_available': True,
            'win32api': SimpleNamespace(GetCurrentThreadId=lambda: 0x1234),
            'win32con': SimpleNamespace(WM_COPYDATA=_WM_COPYDATA),
            'win32ui': SimpleNamespace(FindWindow=self._find_window,
                                       error=_Win32uiError),
            'mmapfile': SimpleNamespace(mmapfile=self._mmapfile,
                                        error=_MmapfileError)
        }

        self._patchers = [
            patch.multiple(agent_win32, create=True, **modules),
            patch('asyncssh.agent.open_agent', agent_win32.open_agent),
            patch.dict(os.environ),
        ]

        for patcher in self._patchers:
            patcher.start()

        os.environ.pop('SSH_AUTH_SOCK', None)
        return self

    def __exit__(self, *exc_info):
        for patcher in reversed(self._patchers):
            patcher.stop()


def _patch_open_file(data=b''):
    """Patch the OpenSSH transport to open an in-memory file"""

    return patch('asyncssh.agent_win32.open_file',
                 return_value=io.BytesIO(data))


class _TestAgentWin32Stub(AsyncTestCase):
    """Unit tests for Windows agent transports using stub pywin32 modules"""

    def test_pywin32_not_available(self):
        """Test finding Pageant when pywin32 isn't installed"""

        with patch.object(agent_win32, '_pywin32_available', False):
            with self.assertRaises(OSError) as exc:
                agent_win32._find_agent_window()

        self.assertEqual(exc.exception.errno, errno.ENOENT)

    def test_pageant_not_found(self):
        """Test finding Pageant when it isn't running"""

        with _StubPageant(window_present=False):
            with self.assertRaises(OSError) as exc:
                agent_win32._find_agent_window()

        self.assertEqual(exc.exception.errno, errno.ENOENT)

    @asynctest
    async def test_pageant_get_keys(self):
        """Test getting keys from Pageant"""

        key = get_test_key('ecdsa-sha2-nistp256')
        response = (Byte(SSH_AGENT_IDENTITIES_ANSWER) + UInt32(1) +
                    String(key.public_data) + String('comment'))

        with _StubPageant(response) as pageant, \
                _patch_open_file() as open_file:
            async with asyncssh.connect_agent() as agent:
                for _ in range(2):
                    keys = await agent.get_keys()

                    self.assertEqual(len(keys), 1)
                    self.assertEqual(keys[0].public_data, key.public_data)
                    self.assertEqual(keys[0].get_comment_bytes(), b'comment')

        open_file.assert_not_called()

        self.assertEqual(pageant.window.requests,
                         2 * [Byte(SSH_AGENTC_REQUEST_IDENTITIES)])

        for mapfile in pageant.mappings.values():
            self.assertTrue(mapfile.closed)

    @asynctest
    async def test_pageant_mapfile_error(self):
        """Test failure to create the Pageant shared memory mapping"""

        with _StubPageant(mmap_fails=True):
            with self.assertRaises(OSError) as exc:
                agent_win32._PageantTransport()

            self.assertEqual(exc.exception.errno, errno.EIO)

            with _patch_open_file() as open_file:
                _, writer = await agent_win32.open_agent('')

            self.assertIsInstance(writer, agent_win32._W10OpenSSHTransport)
            open_file.assert_called_once_with(
                agent_win32._DEFAULT_OPENSSH_PATH, 'r+b')

    @asynctest
    async def test_pageant_multiple_writes(self):
        """Test a request sent to Pageant in multiple writes"""

        response = Byte(SSH_AGENT_IDENTITIES_ANSWER) + UInt32(0)

        with _StubPageant(response) as pageant:
            transport = agent_win32._PageantTransport()
            transport.write(UInt32(1))
            transport.write(Byte(SSH_AGENTC_REQUEST_IDENTITIES))

            self.assertEqual(await transport.readexactly(4),
                             UInt32(len(response)))
            self.assertEqual(await transport.readexactly(len(response)),
                             response)

            transport.close()

        self.assertEqual(pageant.window.requests,
                         [Byte(SSH_AGENTC_REQUEST_IDENTITIES)])

    @asynctest
    async def test_pageant_send_failure(self):
        """Test Pageant rejecting a request"""

        with _StubPageant(send_result=0):
            async with asyncssh.connect_agent() as agent:
                with self.assertRaises(ValueError):
                    await agent.get_keys()

    @asynctest
    async def test_pageant_exited(self):
        """Test Pageant exiting after a connection is opened"""

        with _StubPageant() as pageant:
            async with asyncssh.connect_agent() as agent:
                pageant.window_present = False

                with self.assertRaises(ValueError):
                    await agent.get_keys()

    @asynctest
    async def test_pageant_request_too_large(self):
        """Test sending a request larger than the Pageant mapping"""

        with _StubPageant():
            transport = agent_win32._PageantTransport()

            with self.assertRaises(OSError) as exc:
                transport.write(bytes(agent_win32._AGENT_MAX_MSGLEN + 1))

            self.assertEqual(exc.exception.errno, errno.EIO)

            transport.close()
            await transport.wait_closed()

    @asynctest
    async def test_pageant_short_read(self):
        """Test reading past the end of the Pageant mapping"""

        with _StubPageant():
            transport = agent_win32._PageantTransport()
            transport.write(UInt32(1) + Byte(SSH_AGENTC_REQUEST_IDENTITIES))

            with self.assertRaises(asyncio.IncompleteReadError):
                await transport.readexactly(agent_win32._AGENT_MAX_MSGLEN + 1)

            transport.close()

    @asynctest
    async def test_openssh_default_path(self):
        """Test falling back to the OpenSSH agent when Pageant isn't running"""

        with _StubPageant(window_present=False):
            with _patch_open_file() as open_file:
                _, writer = await agent_win32.open_agent('')

        self.assertIsInstance(writer, agent_win32._W10OpenSSHTransport)
        open_file.assert_called_once_with(
            agent_win32._DEFAULT_OPENSSH_PATH, 'r+b')

    @asynctest
    async def test_openssh_explicit_path(self):
        """Test an explicit agent path being used even if Pageant is running"""

        with _StubPageant():
            with _patch_open_file() as open_file:
                _, writer = await agent_win32.open_agent('agent')

        self.assertIsInstance(writer, agent_win32._W10OpenSSHTransport)
        open_file.assert_called_once_with('agent', 'r+b')

    @asynctest
    async def test_openssh_pipe_busy(self):
        """Test retrying when all instances of the agent pipe are busy"""

        busy = OSError(errno.EINVAL, 'Invalid argument')

        with patch('asyncssh.agent_win32.open_file',
                   side_effect=[busy, busy, io.BytesIO()]) as open_file, \
                patch('asyncssh.agent_win32._wait_named_pipe',
                      return_value=True) as wait_named_pipe:
            _, writer = await agent_win32.open_agent('agent')

        self.assertIsInstance(writer, agent_win32._W10OpenSSHTransport)
        self.assertEqual(open_file.call_count, 3)
        self.assertEqual(wait_named_pipe.call_count, 2)
        wait_named_pipe.assert_called_with('agent',
                                           agent_win32._PIPE_WAIT_TIMEOUT)

    @asynctest
    async def test_openssh_pipe_wait_failed(self):
        """Test failure waiting for the agent pipe to become available"""

        with patch('asyncssh.agent_win32.open_file',
                   side_effect=OSError(errno.EINVAL, 'Invalid argument')), \
                patch('asyncssh.agent_win32._wait_named_pipe',
                      return_value=False) as wait_named_pipe:
            with self.assertRaises(OSError):
                await agent_win32.open_agent('agent')

        wait_named_pipe.assert_called_once()

    @asynctest
    async def test_openssh_pipe_busy_timeout(self):
        """Test giving up when the agent pipe remains busy"""

        with patch('asyncssh.agent_win32.open_file',
                   side_effect=OSError(errno.EINVAL,
                                       'Invalid argument')) as open_file, \
                patch('asyncssh.agent_win32._wait_named_pipe',
                      return_value=True) as wait_named_pipe:
            with self.assertRaises(OSError):
                await agent_win32.open_agent('agent')

        self.assertEqual(open_file.call_count,
                         agent_win32._PIPE_OPEN_ATTEMPTS)
        self.assertEqual(wait_named_pipe.call_count,
                         agent_win32._PIPE_OPEN_ATTEMPTS - 1)

    @asynctest
    async def test_openssh_open_error(self):
        """Test other errors opening the agent pipe not being retried"""

        with patch('asyncssh.agent_win32.open_file',
                   side_effect=OSError(errno.ENOENT, 'Not found')), \
                patch('asyncssh.agent_win32._wait_named_pipe') \
                    as wait_named_pipe:
            with self.assertRaises(OSError):
                await agent_win32.open_agent('agent')

        wait_named_pipe.assert_not_called()

    @asynctest
    async def test_openssh_transport(self):
        """Test reads, writes, and short reads on the OpenSSH transport"""

        with _patch_open_file(b'abc') as open_file:
            reader, writer = await agent_win32.open_agent('agent')

        agentfile = open_file.return_value

        self.assertEqual(await reader.readexactly(2), b'ab')

        with self.assertRaises(asyncio.IncompleteReadError):
            await reader.readexactly(2)

        writer.write(b'xyz')
        self.assertEqual(agentfile.getvalue(), b'abcxyz')

        writer.close()
        await writer.wait_closed()
        self.assertTrue(agentfile.closed)


class _PageantRelay: # pragma: cover only win32
    """A Pageant window which relays requests to the OpenSSH agent

       This creates a real window which receives WM_COPYDATA messages
       the same way Pageant does, reading requests from and writing
       responses to the shared memory mapping named in the message.
       Requests are relayed to the Windows OpenSSH agent.

       The window is created in the calling thread rather than a
       separate one. When asyncssh looks up the window, win32ui
       subclasses it with an MFC window procedure which can only
       dispatch messages in the thread which did the lookup. Messages
       sent from the same thread are delivered by calling the window
       procedure directly, so no message loop is needed.

    """

    def __init__(self, agent_path):
        self._agent = agent_win32._W10OpenSSHTransport(agent_path)
        self._hinst = win32api.GetModuleHandle(None)
        self._atom = None
        self._hwnd = None
        self.errors = []
        self.requests = 0

    def _relay(self, request):
        """Relay a request to the OpenSSH agent and return its response"""

        agentfile = self._agent._agentfile
        agentfile.write(String(request))
        agentfile.flush()

        resplen = int.from_bytes(agentfile.read(4), 'big')
        return String(agentfile.read(resplen))

    def _on_copydata(self, hwnd, msg, wparam, lparam):
        """Handle a WM_COPYDATA agent request"""

        # pylint: disable=unused-argument,broad-except

        try:
            cds = agent_win32._CopyDataStruct.from_address(lparam)

            if cds.dwData != agent_win32._AGENT_COPYDATA_ID:
                raise ValueError('Unexpected copy data ID')

            mapname = cds.lpData.decode()
            mapfile = mmapfile.mmapfile('', mapname,
                                        agent_win32._AGENT_MAX_MSGLEN, 0, 0)

            try:
                reqlen = int.from_bytes(mapfile.read(4), 'big')
                response = self._relay(mapfile.read(reqlen))
                mapfile.seek(0)
                mapfile.write(response)
            finally:
                mapfile.close()

            self.requests += 1
            return 1
        except Exception:
            self.errors.append(traceback.format_exc())
            return 0

    def start(self):
        """Create the Pageant window"""

        wndclass = win32gui.WNDCLASS()
        wndclass.lpszClassName = agent_win32._AGENT_NAME
        wndclass.hInstance = self._hinst
        wndclass.lpfnWndProc = {win32con.WM_COPYDATA: self._on_copydata}

        self._atom = win32gui.RegisterClass(wndclass)
        self._hwnd = win32gui.CreateWindow(
            self._atom, agent_win32._AGENT_NAME, 0, 0, 0, 0, 0,
            0, 0, self._hinst, None)

    def stop(self):
        """Destroy the Pageant window and close the OpenSSH agent"""

        if self._hwnd:
            win32gui.DestroyWindow(self._hwnd)

        if self._atom:
            win32gui.UnregisterClass(agent_win32._AGENT_NAME, self._hinst)

        self._agent.close()


class _WindowsAgentTestCase(AsyncTestCase): # pragma: cover only win32
    """Base class for tests against the Windows OpenSSH agent service"""

    _agent_path = agent_win32._DEFAULT_OPENSSH_PATH

    # pylint: disable=invalid-name

    def setUp(self):
        """Skip tests if the Windows OpenSSH agent isn't running"""

        try:
            agent_win32._W10OpenSSHTransport(self._agent_path).close()
        except OSError:
            self.skipTest('Windows OpenSSH agent not available')

    # pylint: enable=invalid-name

    async def _check_sign(self, agent):
        """Add keys to the agent and check that they can sign"""

        algs = ['ssh-rsa', 'ecdsa-sha2-nistp256']

        if ed25519_available: # pragma: no branch
            algs.append('ssh-ed25519')

        await agent.remove_all()

        try:
            for alg_name in algs:
                key = get_test_key(alg_name)
                pubkey = key.convert_to_public()

                await agent.add_keys([key])
                agent_keys = await agent.get_keys()
                self.assertEqual(len(agent_keys), 1)

                agent_key = agent_keys[0]
                agent_key.set_sig_algorithm(agent_key.sig_algorithms[0])
                sig = await agent_key.sign_async(b'test')
                self.assertTrue(pubkey.verify(b'test', sig))

                await agent.remove_keys(agent_keys)
                self.assertEqual(await agent.get_keys(), [])
        finally:
            await agent.remove_all()



@unittest.skipUnless(sys.platform == 'win32', 'Windows only')
class _TestAgentWin32OpenSSH(_WindowsAgentTestCase): # pragma: cover only win32
    """Unit tests against the Windows OpenSSH agent service"""

    @asynctest
    async def test_default_path(self):
        """Test connecting to the OpenSSH agent at its default path"""

        with patch.dict(os.environ), \
                patch('asyncssh.agent_win32._find_agent_window',
                      side_effect=OSError(errno.ENOENT, 'Agent not found')):
            os.environ.pop('SSH_AUTH_SOCK', None)

            async with asyncssh.connect_agent() as agent:
                await self._check_sign(agent)

    @asynctest
    async def test_explicit_path(self):
        """Test connecting to the OpenSSH agent at an explicit path"""

        async with asyncssh.connect_agent(self._agent_path) as agent:
            await self._check_sign(agent)

    @asynctest
    async def test_reconnect(self):
        """Test reconnecting to the OpenSSH agent after closing it"""

        async with asyncssh.connect_agent(self._agent_path) as agent:
            async with agent:
                await agent.get_keys()

            await self._check_sign(agent)

    def test_wait_named_pipe(self):
        """Test waiting for the agent pipe to become available"""

        self.assertTrue(agent_win32._wait_named_pipe(self._agent_path, 0))

        self.assertFalse(agent_win32._wait_named_pipe(
            r'\\.\pipe\asyncssh-no-such-agent', 0))

    @asynctest
    async def test_concurrent_connections(self):
        """Test several simultaneous connections to the OpenSSH agent"""

        async def get_keys():
            """Open a connection to the agent and request keys"""

            async with asyncssh.connect_agent(self._agent_path) as agent:
                return await agent.get_keys()

        await asyncio.gather(*(get_keys() for _ in range(10)))

    @asynctest
    async def test_connection_failed(self):
        """Test failure connecting to a non-existent agent pipe"""

        with self.assertRaises(OSError):
            await asyncssh.connect_agent(r'\\.\pipe\asyncssh-no-such-agent')


@unittest.skipUnless(sys.platform == 'win32', 'Windows only')
class _TestAgentWin32Pageant(_WindowsAgentTestCase): # pragma: cover only win32
    """Unit tests against a Pageant window relaying to the OpenSSH agent"""

    # pylint: disable=invalid-name

    def setUp(self):
        """Start a Pageant window which relays to the OpenSSH agent"""

        super().setUp()

        try:
            agent_win32._find_agent_window()
        except OSError:
            pass
        else:
            self.skipTest('Pageant already running')

        self._pageant = _PageantRelay(self._agent_path)
        self.addCleanup(self._pageant.stop)
        self.addCleanup(self._check_errors)
        self._pageant.start()

        env_patcher = patch.dict(os.environ)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        os.environ.pop('SSH_AUTH_SOCK', None)

    # pylint: enable=invalid-name

    def _check_errors(self):
        """Check that no errors occurred handling Pageant requests"""

        self.assertEqual(''.join(self._pageant.errors), '')

    def _check_requests(self):
        """Check that requests were sent through the Pageant window"""

        self.assertGreater(self._pageant.requests, 0)

    @asynctest
    async def test_pageant(self):
        """Test adding keys and signing through Pageant"""

        async with asyncssh.connect_agent() as agent:
            await self._check_sign(agent)

            self.assertIsInstance(agent._writer,
                                  agent_win32._PageantTransport)

        self._check_requests()

    @asynctest
    async def test_pageant_reconnect(self):
        """Test reconnecting to Pageant after closing it"""

        async with asyncssh.connect_agent() as agent:
            async with agent:
                await agent.get_keys()

            await self._check_sign(agent)

        self._check_requests()

    @asynctest
    async def test_pageant_large_request(self):
        """Test a request too large for the Pageant shared memory"""

        async with asyncssh.connect_agent() as agent:
            with self.assertRaises(ValueError):
                await agent.sign(b'',
                                 bytes(agent_win32._AGENT_MAX_MSGLEN))
