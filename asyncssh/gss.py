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

"""GSSAPI wrapper"""

import sys

try:
    # pylint: disable=unused-import

    if sys.platform == 'win32': # pragma: no cover
        from .gss_win32 import GSSError, GSSClient, GSSServer
    else:
        from .gss_unix import GSSError, GSSClient, GSSServer

    gss_available = True
except ImportError: # pragma: no cover
    gss_available = False

    class GSSError(ValueError):
        """Stub class for reporting that GSS is not available"""

        def __init__(self, maj_code=0, min_code=0, token=None):
            super().__init__('GSS not available')

            self.maj_code = maj_code
            self.min_code = min_code
            self.token = token


    class GSSClient:
        """Stub client class for reporting that GSS is not available"""

        def __init__(self, host, delegate_creds):
            # pylint: disable=unused-argument

            raise GSSError()


    class GSSServer:
        """Stub client class for reporting that GSS is not available"""

        def __init__(self, host):
            # pylint: disable=unused-argument

            raise GSSError()
