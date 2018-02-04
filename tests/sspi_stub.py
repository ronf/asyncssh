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

"""Stub SSPI module for unit tests"""

from asyncssh.gss_win32 import ASC_RET_INTEGRITY, ISC_RET_INTEGRITY
from asyncssh.gss_win32 import SECPKG_ATTR_NATIVE_NAMES, SSPIError

from .gss_stub import step


class SSPIBuffer:
    """Stub class for SSPI buffer"""

    def __init__(self, data):
        self._data = data

    @property
    def Buffer(self): # pylint: disable=invalid-name
        """Return the data in the buffer"""

        return self._data


class SSPIContext:
    """Stub class for SSPI security context"""

    def QueryContextAttributes(self, attr): # pylint: disable=invalid-name
        """Return principal information associated with this context"""

        # pylint: disable=no-self-use

        if attr == SECPKG_ATTR_NATIVE_NAMES:
            return ['user@TEST', 'host@TEST']
        else:
            return None


class SSPIAuth:
    """Stub class for SSPI authentication"""

    def __init__(self, package=None, spn=None, targetspn=None, scflags=None):
        # pylint: disable=unused-argument

        host = spn or targetspn

        if 'init_error' in host:
            raise SSPIError('Authentication initialization error')

        if targetspn and 'no_client_integrity' in host:
            scflags &= ~ISC_RET_INTEGRITY
        elif spn and 'no_server_integrity' in host:
            scflags &= ~ASC_RET_INTEGRITY

        self._host = host[5:]
        self._flags = scflags
        self._ctxt = SSPIContext()
        self._complete = False
        self._error = False

    @property
    def authenticated(self):
        """Return whether authentication is complete"""

        return self._complete

    @property
    def ctxt(self):
        """Return authentication context"""

        return self._ctxt

    @property
    def ctxt_attr(self):
        """Return authentication flags"""

        return self._flags

    def reset(self):
        """Reset SSPI security context"""

        self._complete = False

    def authorize(self, token):
        """Perform next step in SSPI authentication"""

        if self._error:
            self._error = False
            raise SSPIError('Token authentication errror')

        new_token, complete = step(self._host, token)

        if complete:
            self._complete = True

        if new_token in (b'error', b'errtok'):
            if token:
                raise SSPIError('Token authentication errror')
            else:
                self._error = True
                return True, [SSPIBuffer(b'')]
        else:
            return bool(new_token), [SSPIBuffer(new_token)]

    def sign(self, data):
        """Sign a block of data"""

        # pylint: disable=no-self-use,unused-argument

        return b'fail' if 'fail' in self._host else 'succeed'

    def verify(self, data, sig):
        """Verify a signature for a block of data"""

        # pylint: disable=no-self-use,unused-argument

        if sig == b'fail':
            raise SSPIError('Signature verification error')
