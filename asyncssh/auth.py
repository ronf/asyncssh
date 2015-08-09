# Copyright (c) 2013-2015 by Ron Frederick <ronf@timeheart.net>.
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
from .misc import DisconnectError
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


class _SSHAuthError(Exception):
    """This is raised when we can't proceed with the current form of auth."""


class _ClientAuth(SSHPacketHandler):
    """Parent class for client auth"""

    def __init__(self, conn, method):
        self._conn = conn
        self._method = method

    def auth_succeeded(self):
        """Callback when auth succeeds"""

    def auth_failed(self):
        """Callback when auth fails"""

    def process_packet(self, pkttype, packet):
        try:
            processed = super().process_packet(pkttype, packet)
        except _SSHAuthError:
            # We can't complete the current auth - move to the next one
            processed = True
            self._conn.try_next_auth()

        return processed

    def send_request(self, *args, key=None):
        """Send a user authentication request"""

        self._conn.send_userauth_request(self._method, *args, key=key)


class _ClientNullAuth(_ClientAuth):
    """Client side implementation of null auth"""

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self.send_request()

    packet_handlers = {}


class _ClientPublicKeyAuth(_ClientAuth):
    """Client side implementation of public key auth"""

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self._alg, self._key, self._key_data = conn.public_key_auth_requested()
        if self._alg is None:
            raise _SSHAuthError()

        self.send_request(Boolean(False), String(self._alg),
                          String(self._key_data))

    def _process_public_key_ok(self, pkttype, packet):
        """Process a public key ok response"""

        # pylint: disable=unused-argument

        algorithm = packet.get_string()
        key_data = packet.get_string()
        packet.check_end()

        if algorithm != self._alg or key_data != self._key_data:
            raise DisconnectError(DISC_PROTOCOL_ERROR, 'Key mismatch')

        self.send_request(Boolean(True), String(algorithm),
                          String(key_data), key=self._key)
        return True

    packet_handlers = {
        MSG_USERAUTH_PK_OK: _process_public_key_ok
    }


class _ClientKbdIntAuth(_ClientAuth):
    """Client side implementation of keyboard-interactive auth"""

    def __init__(self, conn, method):
        super().__init__(conn, method)

        submethods = conn.kbdint_auth_requested()
        if submethods is None:
            raise _SSHAuthError()

        self.send_request(String(''), String(submethods))

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

        responses = self._conn.kbdint_challenge_received(name, instruction,
                                                         lang, prompts)

        if responses is None:
            raise _SSHAuthError()

        self._conn.send_packet(Byte(MSG_USERAUTH_INFO_RESPONSE),
                               UInt32(len(responses)),
                               b''.join(String(r) for r in responses))

    packet_handlers = {
        MSG_USERAUTH_INFO_REQUEST: _process_info_request
    }


class _ClientPasswordAuth(_ClientAuth):
    """Client side implementation of password auth"""

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self._password_change = False

        password = conn.password_auth_requested()
        if password is None:
            raise _SSHAuthError()

        self.send_request(Boolean(False), String(password))

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

        result = self._conn.password_change_requested()
        if result == NotImplemented:
            # Password change not supported - move on to the next auth method
            raise _SSHAuthError()
        else:
            old_password, new_password = result

            self._password_change = True

            self.send_request(Boolean(True),
                              String(old_password.encode('utf-8')),
                              String(new_password.encode('utf-8')))

        return True

    packet_handlers = {
        MSG_USERAUTH_PASSWD_CHANGEREQ: _process_password_change
    }


class _ServerAuth(SSHPacketHandler):
    """Parent class for server side auth"""

    def __init__(self, conn, username, packet):
        self._conn = conn
        self._username = username
        self._coro = asyncio.async(self._start(packet))

    @asyncio.coroutine
    def _start(self, packet):
        """Abstract method for starting server authentication"""

        # Provided by subclass
        raise NotImplementedError

    def cancel(self):
        """Cancel any authentication in progress"""

        if self._coro:
            self._coro.cancel()
            self._coro = None

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

        self.cancel()
        self._coro = asyncio.async(self._validate_response(responses))

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

        # TODO: Handle password change request

        if (yield from self._conn.validate_password(self._username, password)):
            self.send_success()
        else:
            self.send_failure()


def register_auth_method(alg, client_handler, server_handler):
    """Register an authentication method"""

    _auth_methods.append(alg)
    _client_auth_handlers[alg] = client_handler
    _server_auth_handlers[alg] = server_handler


def lookup_client_auth(conn, method):
    """Look up the client authentication method to use"""

    if method in _auth_methods:
        try:
            return _client_auth_handlers[method](conn, method)
        except _SSHAuthError:
            pass

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
