# Copyright (c) 2017 by Ron Frederick <ronf@timeheart.net>.
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

"""Stub GSSAPI module for unit tests"""

from asyncssh.gss import GSSError, RequirementFlag


class Name:
    """Stub class for GSS principal name"""

    def __init__(self, base, name_type=None):
        # pylint: disable=unused-argument

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


class SecurityContext:
    """Stub class for GSS security context"""

    def __init__(self, name=None, creds=None, flags=None):
        host = creds.host if creds.server else name.host

        if flags is None:
            flags = set((RequirementFlag.mutual_authentication,
                         RequirementFlag.integrity))

        if ((creds.server and 'no_server_integrity' in host) or
                (not creds.server and 'no_client_integrity' in host)):
            flags.remove(RequirementFlag.integrity)

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

        if token == b'errtok':
            raise GSSError(99, 99, token)
        elif ((token is None and 'empty_init' in self._host) or
              (token == b'1' and 'empty_continue' in self._host)):
            return b''
        elif token == b'0':
            if 'continue_token' in self._host:
                token = b'continue'
            else:
                self._complete = True
                token = b'extra' if 'extra_token' in self._host else None
        elif token:
            token = bytes((token[0]-1,))
        else:
            token = self._host[0].encode('ascii')

        if token == b'0':
            if 'step_error' in self._host:
                errtok = b'errtok' if 'errtok' in self._host else None
                raise GSSError(99, 99, errtok)

            self._complete = True

        return token

    def get_signature(self, data):
        """Sign a block of data"""

        # pylint: disable=no-self-use,unused-argument

        return b'fail' if 'fail' in self._host else 'succeed'

    def verify_signature(self, data, sig):
        """Verify a signature for a block of data"""

        # pylint: disable=no-self-use,unused-argument

        if sig == b'fail':
            raise GSSError(99, 99)
