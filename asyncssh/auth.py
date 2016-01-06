# Copyright (c) 2013-2016 by Ron Frederick <ronf@timeheart.net>.
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

"""SSH authentication handlers"""

import asyncio

from .constants import DISC_PROTOCOL_ERROR
from .misc import DisconnectError, PasswordChangeRequired
from .packet import Boolean, Byte, String, UInt32, SSHPacketHandler
from .saslprep import saslprep, SASLPrepError


# pylint: disable=bad-whitespace

# SSH message values for public key auth
MSG_USERAUTH_PK_OK            = 60

# SSH message values for password auth
MSG_USERAUTH_PASSWD_CHANGEREQ = 60

# SSH message values for 'keyboard-interactive' auth
MSG_USERAUTH_INFO_REQUEST     = 60
MSG_USERAUTH_INFO_RESPONSE    = 61

# pylint: enable=bad-whitespace

_auth_methods = []
_client_auth_handlers = {}
_server_auth_handlers = {}


class _Auth(SSHPacketHandler):
    """Parent class for authentication"""

    def __init__(self, conn, coro):
        self._conn = conn
        self._coro = None

        self.create_task(coro)

    def create_task(self, coro):
        """Create an asynchronous auth task"""

        self.cancel()
        self._coro = self._conn.create_task(coro)

    def cancel(self):
        """Cancel any authentication in progress"""

        if self._coro:
            self._coro.cancel()
            self._coro = None


class _ClientAuth(_Auth):
    """Parent class for client authentication"""

    def __init__(self, conn, method):
        self._method = method

        super().__init__(conn, self._start())

    @asyncio.coroutine
    def _start(self):
        """Abstract method for starting client authentication"""

        # Provided by subclass
        raise NotImplementedError

    def auth_succeeded(self):
        """Callback when auth succeeds"""

    def auth_failed(self):
        """Callback when auth fails"""

    @asyncio.coroutine
    def send_request(self, *args, key=None):
        """Send a user authentication request"""

        yield from self._conn.send_userauth_request(self._method,
                                                    *args, key=key)


class _ClientNullAuth(_ClientAuth):
    """Client side implementation of null auth"""

    @asyncio.coroutine
    def _start(self):
        """Start client null authentication"""

        yield from self.send_request()


class _ClientPublicKeyAuth(_ClientAuth):
    """Client side implementation of public key auth"""

    @asyncio.coroutine
    def _start(self):
        """Start client public key authentication"""

        self._keypair = yield from self._conn.public_key_auth_requested()

        if self._keypair is None:
            self._conn.try_next_auth()
            return

        yield from self.send_request(Boolean(False),
                                     String(self._keypair.algorithm),
                                     String(self._keypair.public_data))

    @asyncio.coroutine
    def _send_signed_request(self):
        """Send signed public key request"""

        yield from self.send_request(Boolean(True),
                                     String(self._keypair.algorithm),
                                     String(self._keypair.public_data),
                                     key=self._keypair)

    def _process_public_key_ok(self, pkttype, packet):
        """Process a public key ok response"""

        # pylint: disable=unused-argument

        algorithm = packet.get_string()
        key_data = packet.get_string()
        packet.check_end()

        if (algorithm != self._keypair.algorithm or
                key_data != self._keypair.public_data):
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Key mismatch')

        self.create_task(self._send_signed_request())
        return True

    packet_handlers = {
        MSG_USERAUTH_PK_OK: _process_public_key_ok
    }


class _ClientKbdIntAuth(_ClientAuth):
    """Client side implementation of keyboard-interactive auth"""

    @asyncio.coroutine
    def _start(self):
        """Start client keyboard interactive authentication"""

        submethods = yield from self._conn.kbdint_auth_requested()

        if submethods is None:
            self._conn.try_next_auth()
            return

        yield from self.send_request(String(''), String(submethods))

    @asyncio.coroutine
    def _receive_challenge(self, name, instruction, lang, prompts):
        """Receive and respond to a keyboard interactive challenge"""

        responses = \
            yield from self._conn.kbdint_challenge_received(name, instruction,
                                                            lang, prompts)

        if responses is None:
            self._conn.try_next_auth()
            return

        self._conn.send_packet(Byte(MSG_USERAUTH_INFO_RESPONSE),
                               UInt32(len(responses)),
                               b''.join(String(r) for r in responses))

    def _process_info_request(self, pkttype, packet):
        """Process a keyboard interactive authentication request"""

        # pylint: disable=unused-argument

        name = packet.get_string()
        instruction = packet.get_string()
        lang = packet.get_string()

        try:
            name = name.decode('utf-8')
            instruction = instruction.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid keyboard '
                                  'interactive info request') from None

        num_prompts = packet.get_uint32()
        prompts = []
        for _ in range(num_prompts):
            prompt = packet.get_string()
            echo = packet.get_boolean()

            try:
                prompt = prompt.decode('utf-8')
            except UnicodeDecodeError:
                raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid keyboard '
                                      'interactive info request') from None

            prompts.append((prompt, echo))

        self.create_task(self._receive_challenge(name, instruction,
                                                 lang, prompts))

        return True

    packet_handlers = {
        MSG_USERAUTH_INFO_REQUEST: _process_info_request
    }


class _ClientPasswordAuth(_ClientAuth):
    """Client side implementation of password auth"""

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self._password_change = False

    @asyncio.coroutine
    def _start(self):
        """Start client password authentication"""

        password = yield from self._conn.password_auth_requested()

        if password is None:
            self._conn.try_next_auth()
            return

        yield from self.send_request(Boolean(False), String(password))

    @asyncio.coroutine
    def _change_password(self, prompt, lang):
        """Start password change"""

        result = yield from self._conn.password_change_requested(prompt, lang)

        if result == NotImplemented:
            # Password change not supported - move on to the next auth method
            self._conn.try_next_auth()
            return

        old_password, new_password = result

        self._password_change = True

        yield from self.send_request(Boolean(True),
                                     String(old_password.encode('utf-8')),
                                     String(new_password.encode('utf-8')))

    def auth_succeeded(self):
        if self._password_change:
            self._password_change = False
            self._conn.password_changed()

    def auth_failed(self):
        if self._password_change:
            self._password_change = False
            self._conn.password_change_failed()

    def _process_password_change(self, pkttype, packet):
        """Process a password change request"""

        # pylint: disable=unused-argument

        prompt = packet.get_string()
        lang = packet.get_string()

        try:
            prompt = prompt.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR,
                                  'Invalid password change request') from None

        self.auth_failed()
        self.create_task(self._change_password(prompt, lang))

        return True

    packet_handlers = {
        MSG_USERAUTH_PASSWD_CHANGEREQ: _process_password_change
    }


class _ServerAuth(_Auth):
    """Parent class for server authentication"""

    def __init__(self, conn, username, packet):
        self._username = username

        super().__init__(conn, self._start(packet))

    @asyncio.coroutine
    def _start(self, packet):
        """Abstract method for starting server authentication"""

        # Provided by subclass
        raise NotImplementedError

    def send_failure(self, partial_success=False):
        """Send a user authentication failure response"""

        self._conn.send_userauth_failure(partial_success)

    def send_success(self):
        """Send a user authentication success response"""

        self._conn.send_userauth_success()


class _ServerNullAuth(_ServerAuth):
    """Server side implementation of null auth"""

    @classmethod
    def supported(cls, conn):
        """Return that null authentication is never a supported auth mode"""

        # pylint: disable=unused-argument
        return False

    @asyncio.coroutine
    def _start(self, packet):
        """Always fail null server authentication"""

        packet.check_end()
        self.send_failure()

class _ServerPublicKeyAuth(_ServerAuth):
    """Server side implementation of public key auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether public key authentication is supported"""

        return conn.public_key_auth_supported()

    @asyncio.coroutine
    def _start(self, packet):
        """Start server public key authentication"""

        sig_present = packet.get_boolean()
        algorithm = packet.get_string()
        key_data = packet.get_string()

        if sig_present:
            msg = packet.get_consumed_payload()
            signature = packet.get_string()
        else:
            msg = None
            signature = None

        packet.check_end()

        if (yield from self._conn.validate_public_key(self._username, key_data,
                                                      msg, signature)):
            if sig_present:
                self.send_success()
            else:
                self._conn.send_packet(Byte(MSG_USERAUTH_PK_OK),
                                       String(algorithm), String(key_data))
        else:
            self.send_failure()


class _ServerKbdIntAuth(_ServerAuth):
    """Server side implementation of keyboard-interactive auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether keyboard interactive authentication is supported"""

        return conn.kbdint_auth_supported()

    @asyncio.coroutine
    def _start(self, packet):
        """Start server keyboard interactive authentication"""

        lang = packet.get_string()
        submethods = packet.get_string()
        packet.check_end()

        try:
            lang = lang.decode('ascii')
            submethods = submethods.decode('utf-8')
        except UnicodeDecodeError:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid keyboard '
                                  'interactive auth request') from None

        challenge = yield from self._conn.get_kbdint_challenge(self._username,
                                                               lang,
                                                               submethods)
        self._send_challenge(challenge)

    def _send_challenge(self, challenge):
        """Send a keyboard interactive authentication request"""

        if isinstance(challenge, (tuple, list)):
            name, instruction, lang, prompts = challenge

            num_prompts = len(prompts)
            prompts = (String(prompt) + Boolean(echo)
                       for prompt, echo in prompts)

            self._conn.send_packet(Byte(MSG_USERAUTH_INFO_REQUEST),
                                   String(name), String(instruction),
                                   String(lang), UInt32(num_prompts),
                                   *prompts)
        elif challenge:
            self.send_success()
        else:
            self.send_failure()

    @asyncio.coroutine
    def _validate_response(self, responses):
        """Validate a keyboard interactive authentication response"""

        next_challenge = \
            yield from self._conn.validate_kbdint_response(self._username,
                                                           responses)
        self._send_challenge(next_challenge)

    def _process_info_response(self, pkttype, packet):
        """Process a keyboard interactive authentication response"""

        # pylint: disable=unused-argument

        num_responses = packet.get_uint32()
        responses = []
        for _ in range(num_responses):
            response = packet.get_string()

            try:
                response = response.decode('utf-8')
            except UnicodeDecodeError:
                raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid keyboard '
                                      'interactive info response') from None

            responses.append(response)

        packet.check_end()

        self.create_task(self._validate_response(responses))

    packet_handlers = {
        MSG_USERAUTH_INFO_RESPONSE: _process_info_response
    }


class _ServerPasswordAuth(_ServerAuth):
    """Server side implementation of password auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether password authentication is supported"""

        return conn.password_auth_supported()

    @asyncio.coroutine
    def _start(self, packet):
        """Start server password authentication"""

        password_change = packet.get_boolean()
        password = packet.get_string()
        new_password = packet.get_string() if password_change else b''
        packet.check_end()

        try:
            password = saslprep(password.decode('utf-8'))
            new_password = saslprep(new_password.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError):
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Invalid password auth '
                                  'request') from None

        try:
            if password_change:
                result = yield from self._conn.change_password(self._username,
                                                               password,
                                                               new_password)
            else:
                result = \
                    yield from self._conn.validate_password(self._username,
                                                            password)

            if result:
                self.send_success()
            else:
                self.send_failure()
        except PasswordChangeRequired as exc:
            self._conn.send_packet(Byte(MSG_USERAUTH_PASSWD_CHANGEREQ),
                                   String(exc.prompt), String(exc.lang))


def register_auth_method(alg, client_handler, server_handler):
    """Register an authentication method"""

    _auth_methods.append(alg)
    _client_auth_handlers[alg] = client_handler
    _server_auth_handlers[alg] = server_handler


def lookup_client_auth(conn, method):
    """Look up the client authentication method to use"""

    if method in _auth_methods:
        return _client_auth_handlers[method](conn, method)
    else:
        return None


def get_server_auth_methods(conn):
    """Return a list of supported auth methods"""

    auth_methods = []

    for method in _auth_methods:
        if _server_auth_handlers[method].supported(conn):
            auth_methods.append(method)

    return auth_methods


def lookup_server_auth(conn, username, method, packet):
    """Look up the server authentication method to use"""

    if method in _auth_methods:
        return _server_auth_handlers[method](conn, username, packet)
    else:
        conn.send_userauth_failure(False)
        return None

# pylint: disable=bad-whitespace

_auth_method_list = (
    (b'none',                 _ClientNullAuth,      _ServerNullAuth),
    (b'publickey',            _ClientPublicKeyAuth, _ServerPublicKeyAuth),
    (b'keyboard-interactive', _ClientKbdIntAuth,    _ServerKbdIntAuth),
    (b'password',             _ClientPasswordAuth,  _ServerPasswordAuth)
)

# pylint: enable=bad-whitespace

for _args in _auth_method_list:
    register_auth_method(*_args)
