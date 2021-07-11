# Copyright (c) 2013-2021 by Ron Frederick <ronf@timeheart.net> and others.
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

"""SSH authentication handlers"""

from .constants import DEFAULT_LANG

from .gss import GSSError

from .misc import ProtocolError, PasswordChangeRequired, get_symbol_names

from .packet import Boolean, String, UInt32, SSHPacketHandler

from .saslprep import saslprep, SASLPrepError


# SSH message values for GSS auth
MSG_USERAUTH_GSSAPI_RESPONSE          = 60
MSG_USERAUTH_GSSAPI_TOKEN             = 61
MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63
MSG_USERAUTH_GSSAPI_ERROR             = 64
MSG_USERAUTH_GSSAPI_ERRTOK            = 65
MSG_USERAUTH_GSSAPI_MIC               = 66

# SSH message values for public key auth
MSG_USERAUTH_PK_OK                    = 60

# SSH message values for keyboard-interactive auth
MSG_USERAUTH_INFO_REQUEST             = 60
MSG_USERAUTH_INFO_RESPONSE            = 61

# SSH message values for password auth
MSG_USERAUTH_PASSWD_CHANGEREQ         = 60

_auth_methods = []
_client_auth_handlers = {}
_server_auth_handlers = {}


class _Auth(SSHPacketHandler):
    """Parent class for authentication"""

    def __init__(self, conn, coro):
        self._conn = conn
        self._logger = conn.logger
        self._coro = conn.create_task(coro)

    def send_packet(self, pkttype, *args, trivial=True):
        """Send an auth packet"""

        self._conn.send_userauth_packet(pkttype, *args, handler=self,
                                        trivial=trivial)

    @property
    def logger(self):
        """A logger associated with this authentication handler"""

        return self._logger

    def create_task(self, coro):
        """Create an asynchronous auth task"""

        self.cancel()
        self._coro = self._conn.create_task(coro)

    def cancel(self):
        """Cancel any authentication in progress"""

        if self._coro: # pragma: no branch
            self._coro.cancel()
            self._coro = None


class _ClientAuth(_Auth):
    """Parent class for client authentication"""

    def __init__(self, conn, method):
        self._method = method

        super().__init__(conn, self._start())

    async def _start(self):
        """Abstract method for starting client authentication"""

        # Provided by subclass
        raise NotImplementedError

    def auth_succeeded(self):
        """Callback when auth succeeds"""

    def auth_failed(self):
        """Callback when auth fails"""

    async def send_request(self, *args, key=None, trivial=True):
        """Send a user authentication request"""

        await self._conn.send_userauth_request(self._method, *args, key=key,
                                               trivial=trivial)


class _ClientNullAuth(_ClientAuth):
    """Client side implementation of null auth"""

    async def _start(self):
        """Start client null authentication"""

        await self.send_request()


class _ClientGSSKexAuth(_ClientAuth):
    """Client side implementation of GSS key exchange auth"""

    async def _start(self):
        """Start client GSS key exchange authentication"""

        if self._conn.gss_kex_auth_requested():
            self.logger.debug1('Trying GSS key exchange auth')

            await self.send_request(key=self._conn.get_gss_context(),
                                    trivial=False)
        else:
            self._conn.try_next_auth()


class _ClientGSSMICAuth(_ClientAuth):
    """Client side implementation of GSS MIC auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_GSSAPI_')

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self._gss = None
        self._got_error = False

    async def _start(self):
        """Start client GSS MIC authentication"""

        if self._conn.gss_mic_auth_requested():
            self.logger.debug1('Trying GSS MIC auth')

            self._gss = self._conn.get_gss_context()
            self._gss.reset()
            mechs = b''.join((String(mech) for mech in self._gss.mechs))
            await self.send_request(UInt32(len(self._gss.mechs)), mechs)
        else:
            self._conn.try_next_auth()

    def _finish(self):
        """Finish client GSS MIC authentication"""

        if self._gss.provides_integrity:
            data = self._conn.get_userauth_request_data(self._method)

            self.send_packet(MSG_USERAUTH_GSSAPI_MIC,
                             String(self._gss.sign(data)),
                             trivial=False)
        else:
            self.send_packet(MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)

    def _process_response(self, _pkttype, _pktid, packet):
        """Process a GSS response from the server"""

        mech = packet.get_string()
        packet.check_end()

        if mech not in self._gss.mechs:
            raise ProtocolError('Mechanism mismatch')

        try:
            token = self._gss.step()

            self.send_packet(MSG_USERAUTH_GSSAPI_TOKEN, String(token))

            if self._gss.complete:
                self._finish()
        except GSSError as exc:
            if exc.token:
                self.send_packet(MSG_USERAUTH_GSSAPI_ERRTOK, String(exc.token))

            self._conn.try_next_auth()

        return True

    def _process_token(self, _pkttype, _pktid, packet):
        """Process a GSS token from the server"""

        token = packet.get_string()
        packet.check_end()

        try:
            token = self._gss.step(token)

            if token:
                self.send_packet(MSG_USERAUTH_GSSAPI_TOKEN, String(token))

            if self._gss.complete:
                self._finish()
        except GSSError as exc:
            if exc.token:
                self.send_packet(MSG_USERAUTH_GSSAPI_ERRTOK, String(exc.token))

            self._conn.try_next_auth()

        return True

    def _process_error(self, _pkttype, _pktid, packet):
        """Process a GSS error from the server"""

        _ = packet.get_uint32()         # major_status
        _ = packet.get_uint32()         # minor_status
        msg = packet.get_string()
        _ = packet.get_string()         # lang
        packet.check_end()

        self.logger.debug1('GSS error from server: %s', msg)
        self._got_error = True

        return True

    def _process_error_token(self, _pkttype, _pktid, packet):
        """Process a GSS error token from the server"""

        token = packet.get_string()
        packet.check_end()

        try:
            self._gss.step(token)
        except GSSError as exc:
            if not self._got_error: # pragma: no cover
                self.logger.debug1('GSS error from server: %s', str(exc))

        return True

    _packet_handlers = {
        MSG_USERAUTH_GSSAPI_RESPONSE: _process_response,
        MSG_USERAUTH_GSSAPI_TOKEN:    _process_token,
        MSG_USERAUTH_GSSAPI_ERROR:    _process_error,
        MSG_USERAUTH_GSSAPI_ERRTOK:   _process_error_token
    }


class _ClientHostBasedAuth(_ClientAuth):
    """Client side implementation of host based auth"""

    async def _start(self):
        """Start client host based authentication"""

        keypair, client_host, client_username = \
            await self._conn.host_based_auth_requested()

        if keypair is None:
            self._conn.try_next_auth()
            return

        self.logger.debug1('Trying host based auth of user %s on host %s '
                           'with %s host key', client_username, client_host,
                           keypair.algorithm)

        try:
            await self.send_request(String(keypair.algorithm),
                                    String(keypair.public_data),
                                    String(client_host),
                                    String(client_username), key=keypair)
        except ValueError as exc:
            self.logger.debug1('Host based auth failed: %s', exc)
            self._conn.try_next_auth()


class _ClientPublicKeyAuth(_ClientAuth):
    """Client side implementation of public key auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_PK_')

    async def _start(self):
        """Start client public key authentication"""

        self._keypair = await self._conn.public_key_auth_requested()

        if self._keypair is None:
            self._conn.try_next_auth()
            return

        self.logger.debug1('Trying public key auth with %s key',
                           self._keypair.algorithm)

        await self.send_request(Boolean(False),
                                String(self._keypair.algorithm),
                                String(self._keypair.public_data))

    async def _send_signed_request(self):
        """Send signed public key request"""

        self.logger.debug1('Signing request with %s key',
                           self._keypair.algorithm)

        await self.send_request(Boolean(True),
                                String(self._keypair.algorithm),
                                String(self._keypair.public_data),
                                key=self._keypair, trivial=False)

    def _process_public_key_ok(self, _pkttype, _pktid, packet):
        """Process a public key ok response"""

        algorithm = packet.get_string()
        key_data = packet.get_string()
        packet.check_end()

        if (algorithm != self._keypair.algorithm or
                key_data != self._keypair.public_data):
            raise ProtocolError('Key mismatch')

        self.create_task(self._send_signed_request())
        return True

    _packet_handlers = {
        MSG_USERAUTH_PK_OK: _process_public_key_ok
    }


class _ClientKbdIntAuth(_ClientAuth):
    """Client side implementation of keyboard-interactive auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_INFO_')

    async def _start(self):
        """Start client keyboard interactive authentication"""

        submethods = await self._conn.kbdint_auth_requested()

        if submethods is None:
            self._conn.try_next_auth()
            return

        self.logger.debug1('Trying keyboard-interactive auth')

        await self.send_request(String(''), String(submethods))

    async def _receive_challenge(self, name, instruction, lang, prompts):
        """Receive and respond to a keyboard interactive challenge"""

        responses = \
            await self._conn.kbdint_challenge_received(name, instruction,
                                                       lang, prompts)

        if responses is None:
            self._conn.try_next_auth()
            return

        self.send_packet(MSG_USERAUTH_INFO_RESPONSE, UInt32(len(responses)),
                         b''.join(String(r) for r in responses),
                         trivial=not responses)

    def _process_info_request(self, _pkttype, _pktid, packet):
        """Process a keyboard interactive authentication request"""

        name = packet.get_string()
        instruction = packet.get_string()
        lang = packet.get_string()

        try:
            name = name.decode('utf-8')
            instruction = instruction.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid keyboard interactive '
                                'info request') from None

        num_prompts = packet.get_uint32()
        prompts = []
        for _ in range(num_prompts):
            prompt = packet.get_string()
            echo = packet.get_boolean()

            try:
                prompt = prompt.decode('utf-8')
            except UnicodeDecodeError:
                raise ProtocolError('Invalid keyboard interactive '
                                    'info request') from None

            prompts.append((prompt, echo))

        self.create_task(self._receive_challenge(name, instruction,
                                                 lang, prompts))

        return True

    _packet_handlers = {
        MSG_USERAUTH_INFO_REQUEST: _process_info_request
    }


class _ClientPasswordAuth(_ClientAuth):
    """Client side implementation of password auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_PASSWD_')

    def __init__(self, conn, method):
        super().__init__(conn, method)

        self._password_change = False

    async def _start(self):
        """Start client password authentication"""

        password = await self._conn.password_auth_requested()

        if password is None:
            self._conn.try_next_auth()
            return

        self.logger.debug1('Trying password auth')

        await self.send_request(Boolean(False), String(password),
                                trivial=False)

    async def _change_password(self, prompt, lang):
        """Start password change"""

        result = await self._conn.password_change_requested(prompt, lang)

        if result == NotImplemented:
            # Password change not supported - move on to the next auth method
            self._conn.try_next_auth()
            return

        self.logger.debug1('Trying to chsnge password')

        old_password, new_password = result

        self._password_change = True

        await self.send_request(Boolean(True),
                                String(old_password.encode('utf-8')),
                                String(new_password.encode('utf-8')),
                                trivial=False)

    def auth_succeeded(self):
        if self._password_change:
            self._password_change = False
            self._conn.password_changed()

    def auth_failed(self):
        if self._password_change:
            self._password_change = False
            self._conn.password_change_failed()

    def _process_password_change(self, _pkttype, _pktid, packet):
        """Process a password change request"""

        prompt = packet.get_string()
        lang = packet.get_string()

        try:
            prompt = prompt.decode('utf-8')
            lang = lang.decode('ascii')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid password change request') from None

        self.auth_failed()
        self.create_task(self._change_password(prompt, lang))

        return True

    _packet_handlers = {
        MSG_USERAUTH_PASSWD_CHANGEREQ: _process_password_change
    }


class _ServerAuth(_Auth):
    """Parent class for server authentication"""

    def __init__(self, conn, username, method, packet):
        self._username = username
        self._method = method

        super().__init__(conn, self._start(packet))

    async def _start(self, packet):
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
    def supported(cls, _conn):
        """Return that null authentication is never a supported auth mode"""

        return False

    async def _start(self, packet):
        """Supported always returns false, so we never get here"""


class _ServerGSSKexAuth(_ServerAuth):
    """Server side implementation of GSS key exchange auth"""

    def __init__(self, conn, username, method, packet):
        super().__init__(conn, username, method, packet)

        self._gss = conn.get_gss_context()

    @classmethod
    def supported(cls, conn):
        """Return whether GSS key exchange authentication is supported"""

        return conn.gss_kex_auth_supported()

    async def _start(self, packet):
        """Start server GSS key exchange authentication"""

        mic = packet.get_string()
        packet.check_end()

        self.logger.debug1('Trying GSS key exchange auth')

        data = self._conn.get_userauth_request_data(self._method)

        if (self._gss.complete and self._gss.verify(data, mic) and
                (await self._conn.validate_gss_principal(self._username,
                                                         self._gss.user,
                                                         self._gss.host))):
            self.send_success()
        else:
            self.send_failure()


class _ServerGSSMICAuth(_ServerAuth):
    """Server side implementation of GSS MIC auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_GSSAPI_')

    def __init__(self, conn, username, method, packet):
        super().__init__(conn, username, method, packet)

        self._gss = conn.get_gss_context()

    @classmethod
    def supported(cls, conn):
        """Return whether GSS MIC authentication is supported"""

        return conn.gss_mic_auth_supported()

    async def _start(self, packet):
        """Start server GSS MIC authentication"""

        mechs = set()

        n = packet.get_uint32()
        for _ in range(n):
            mechs.add(packet.get_string())
        packet.check_end()

        match = None

        for mech in self._gss.mechs:
            if mech in mechs:
                match = mech
                break

        if not match:
            self.send_failure()
            return

        self.logger.debug1('Trying GSS MIC auth')

        self.send_packet(MSG_USERAUTH_GSSAPI_RESPONSE, String(match))

    async def _finish(self):
        """Finish server GSS MIC authentication"""

        if (await self._conn.validate_gss_principal(self._username,
                                                    self._gss.user,
                                                    self._gss.host)):
            self.send_success()
        else:
            self.send_failure()

    def _process_token(self, _pkttype, _pktid, packet):
        """Process a GSS token from the client"""

        token = packet.get_string()
        packet.check_end()

        try:
            token = self._gss.step(token)

            if token:
                self.send_packet(MSG_USERAUTH_GSSAPI_TOKEN, String(token))
        except GSSError as exc:
            self.send_packet(MSG_USERAUTH_GSSAPI_ERROR, UInt32(exc.maj_code),
                             UInt32(exc.min_code), String(str(exc)),
                             String(DEFAULT_LANG))

            if exc.token:
                self.send_packet(MSG_USERAUTH_GSSAPI_ERRTOK, String(exc.token))

            self.send_failure()

        return True

    def _process_exchange_complete(self, _pkttype, _pktid, packet):
        """Process a GSS exchange complete message from the client"""

        packet.check_end()

        if self._gss.complete and not self._gss.provides_integrity:
            self.create_task(self._finish())
        else:
            self.send_failure()

        return True

    def _process_error_token(self, _pkttype, _pktid, packet):
        """Process a GSS error token from the client"""

        token = packet.get_string()
        packet.check_end()

        try:
            self._gss.step(token)
        except GSSError as exc:
            self.logger.debug1('GSS error from client: %s', str(exc))

        return True

    def _process_mic(self, _pkttype, _pktid, packet):
        """Process a GSS MIC from the client"""

        mic = packet.get_string()
        packet.check_end()

        data = self._conn.get_userauth_request_data(self._method)

        if (self._gss.complete and self._gss.provides_integrity and
                self._gss.verify(data, mic)):
            self.create_task(self._finish())
        else:
            self.send_failure()

        return True

    _packet_handlers = {
        MSG_USERAUTH_GSSAPI_TOKEN:             _process_token,
        MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE: _process_exchange_complete,
        MSG_USERAUTH_GSSAPI_ERRTOK:            _process_error_token,
        MSG_USERAUTH_GSSAPI_MIC:               _process_mic
    }


class _ServerHostBasedAuth(_ServerAuth):
    """Server side implementation of host based auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether host based authentication is supported"""

        return conn.host_based_auth_supported()

    async def _start(self, packet):
        """Start server host based authentication"""

        algorithm = packet.get_string()
        key_data = packet.get_string()
        client_host = packet.get_string()
        client_username = packet.get_string()
        msg = packet.get_consumed_payload()
        signature = packet.get_string()

        packet.check_end()

        try:
            client_host = client_host.decode('utf-8')
            client_username = saslprep(client_username.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError):
            raise ProtocolError('Invalid host-based auth request') from None

        self.logger.debug1('Verifying host based auth of user %s '
                           'on host %s with %s host key', client_username,
                           client_host, algorithm)

        if (await self._conn.validate_host_based_auth(self._username,
                                                      key_data, client_host,
                                                      client_username,
                                                      msg, signature)):
            self.send_success()
        else:
            self.send_failure()


class _ServerPublicKeyAuth(_ServerAuth):
    """Server side implementation of public key auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether public key authentication is supported"""

        return conn.public_key_auth_supported()

    async def _start(self, packet):
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

        if sig_present:
            self.logger.debug1('Verifying request with %s key', algorithm)
        else:
            self.logger.debug1('Trying public key auth with %s key', algorithm)

        if (await self._conn.validate_public_key(self._username, key_data,
                                                 msg, signature)):
            if sig_present:
                self.send_success()
            else:
                self.send_packet(MSG_USERAUTH_PK_OK, String(algorithm),
                                 String(key_data))
        else:
            self.send_failure()


class _ServerKbdIntAuth(_ServerAuth):
    """Server side implementation of keyboard-interactive auth"""

    _handler_names = get_symbol_names(globals(), 'MSG_USERAUTH_INFO_')

    @classmethod
    def supported(cls, conn):
        """Return whether keyboard interactive authentication is supported"""

        return conn.kbdint_auth_supported()

    async def _start(self, packet):
        """Start server keyboard interactive authentication"""

        lang = packet.get_string()
        submethods = packet.get_string()
        packet.check_end()

        try:
            lang = lang.decode('ascii')
            submethods = submethods.decode('utf-8')
        except UnicodeDecodeError:
            raise ProtocolError('Invalid keyboard interactive '
                                'auth request') from None

        self.logger.debug1('Trying keyboard-interactive auth')

        challenge = await self._conn.get_kbdint_challenge(self._username,
                                                          lang, submethods)
        self._send_challenge(challenge)

    def _send_challenge(self, challenge):
        """Send a keyboard interactive authentication request"""

        if isinstance(challenge, (tuple, list)):
            name, instruction, lang, prompts = challenge

            num_prompts = len(prompts)
            prompts = (String(prompt) + Boolean(echo)
                       for prompt, echo in prompts)

            self.send_packet(MSG_USERAUTH_INFO_REQUEST, String(name),
                             String(instruction), String(lang),
                             UInt32(num_prompts), *prompts)
        elif challenge:
            self.send_success()
        else:
            self.send_failure()

    async def _validate_response(self, responses):
        """Validate a keyboard interactive authentication response"""

        next_challenge = \
            await self._conn.validate_kbdint_response(self._username, responses)
        self._send_challenge(next_challenge)

    def _process_info_response(self, _pkttype, _pktid, packet):
        """Process a keyboard interactive authentication response"""

        num_responses = packet.get_uint32()
        responses = []
        for _ in range(num_responses):
            response = packet.get_string()

            try:
                response = response.decode('utf-8')
            except UnicodeDecodeError:
                raise ProtocolError('Invalid keyboard interactive '
                                    'info response') from None

            responses.append(response)

        packet.check_end()

        self.create_task(self._validate_response(responses))
        return True

    _packet_handlers = {
        MSG_USERAUTH_INFO_RESPONSE: _process_info_response
    }


class _ServerPasswordAuth(_ServerAuth):
    """Server side implementation of password auth"""

    @classmethod
    def supported(cls, conn):
        """Return whether password authentication is supported"""

        return conn.password_auth_supported()

    async def _start(self, packet):
        """Start server password authentication"""

        password_change = packet.get_boolean()
        password = packet.get_string()
        new_password = packet.get_string() if password_change else b''
        packet.check_end()

        try:
            password = saslprep(password.decode('utf-8'))
            new_password = saslprep(new_password.decode('utf-8'))
        except (UnicodeDecodeError, SASLPrepError):
            raise ProtocolError('Invalid password auth request') from None

        try:
            if password_change:
                self.logger.debug1('Trying to chsnge password')

                result = await self._conn.change_password(self._username,
                                                          password,
                                                          new_password)
            else:
                self.logger.debug1('Trying password auth')

                result = \
                    await self._conn.validate_password(self._username, password)

            if result:
                self.send_success()
            else:
                self.send_failure()
        except PasswordChangeRequired as exc:
            self.send_packet(MSG_USERAUTH_PASSWD_CHANGEREQ,
                             String(exc.prompt), String(exc.lang))


def register_auth_method(alg, client_handler, server_handler):
    """Register an authentication method"""

    _auth_methods.append(alg)
    _client_auth_handlers[alg] = client_handler
    _server_auth_handlers[alg] = server_handler


def get_client_auth_methods():
    """Return a list of supported client auth methods"""

    return [method for method in _client_auth_handlers
            if method != b'none']


def lookup_client_auth(conn, method):
    """Look up the client authentication method to use"""

    if method in _auth_methods:
        return _client_auth_handlers[method](conn, method)
    else:
        return None


def get_server_auth_methods(conn):
    """Return a list of supported server auth methods"""

    auth_methods = []

    for method in _auth_methods:
        if _server_auth_handlers[method].supported(conn):
            auth_methods.append(method)

    return auth_methods


def lookup_server_auth(conn, username, method, packet):
    """Look up the server authentication method to use"""

    handler = _server_auth_handlers.get(method)

    if handler and handler.supported(conn):
        return handler(conn, username, method, packet)
    else:
        conn.send_userauth_failure(False)
        return None


_auth_method_list = (
    (b'none',                 _ClientNullAuth,      _ServerNullAuth),
    (b'gssapi-keyex',         _ClientGSSKexAuth,    _ServerGSSKexAuth),
    (b'gssapi-with-mic',      _ClientGSSMICAuth,    _ServerGSSMICAuth),
    (b'hostbased',            _ClientHostBasedAuth, _ServerHostBasedAuth),
    (b'publickey',            _ClientPublicKeyAuth, _ServerPublicKeyAuth),
    (b'keyboard-interactive', _ClientKbdIntAuth,    _ServerKbdIntAuth),
    (b'password',             _ClientPasswordAuth,  _ServerPasswordAuth)
)

for _args in _auth_method_list:
    register_auth_method(*_args)
