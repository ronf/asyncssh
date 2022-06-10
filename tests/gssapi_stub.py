# Copyright (c) 2017-2019 by Ron Frederick <ronf@timeheart.net> and others.
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

"""Stub GSSAPI module for unit tests"""

from enum import IntEnum

from asyncssh.gss import GSSError

from .gss_stub import step


class Name:
    """Stub class for GSS principal name"""

    def __init__(self, base, _name_type=None):
        if 'init_error' in base:
            raise GSSError(99, 99)

        self.host = base[5:]


class Credentials:
    """Stub class for GSS credentials"""

    def __init__(self, name=None, usage=None):
        self.host = name.host if name else ''
        self.server = usage == 'accept'

    @property
    def mechs(self):
        """Return GSS mechanisms available for this host"""

        if self.server:
            return [0] if 'unknown_mech' in self.host else [1, 2]
        else:
            return [2]


class RequirementFlag(IntEnum):
    """Stub class for GSS requirement flags"""

    # pylint: disable=invalid-name

    delegate_to_peer = 1
    mutual_authentication = 2
    integrity = 4


class SecurityContext:
    """Stub class for GSS security context"""

    def __init__(self, name=None, creds=None, flags=None):
        host = creds.host if creds.server else name.host

        if flags is None:
            flags = RequirementFlag.mutual_authentication | \
                    RequirementFlag.integrity

        if ((creds.server and 'no_server_integrity' in host) or
                (not creds.server and 'no_client_integrity' in host)):
            flags &= ~RequirementFlag.integrity

        self._host = host
        self._server = creds.server
        self._actual_flags = flags
        self._complete = False

    @property
    def complete(self):
        """Return whether or not GSS negotiation is complete"""

        return self._complete

    @property
    def actual_flags(self):
        """Return flags set on this context"""

        return self._actual_flags

    @property
    def initiator_name(self):
        """Return user principal associated with this context"""

        return 'user@TEST'

    @property
    def target_name(self):
        """Return host principal associated with this context"""

        return 'host@TEST'

    def step(self, token=None):
        """Perform next step in GSS security exchange"""

        token, complete = step(self._host, token)

        if complete:
            self._complete = True

        if token == b'error':
            raise GSSError(99, 99)
        elif token == b'errtok':
            raise GSSError(99, 99, token)
        else:
            return token

    def get_signature(self, _data):
        """Sign a block of data"""

        if 'sign_error' in self._host:
            raise GSSError(99, 99)

        return b'fail' if 'verify_error' in self._host else b''

    def verify_signature(self, _data, sig):
        """Verify a signature for a block of data"""

        # pylint: disable=no-self-use

        if sig == b'fail':
            raise GSSError(99, 99)
