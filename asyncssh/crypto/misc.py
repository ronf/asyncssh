# Copyright (c) 2017-2018 by Ron Frederick <ronf@timeheart.net>.
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

"""Miscellaneous PyCA utility classes and functions"""

class PyCAKey:
    """Base class for PyCA private/public keys"""

    def __init__(self, pyca_key):
        self._pyca_key = pyca_key

    @property
    def pyca_key(self):
        """Return the PyCA object associated with this key"""

        return self._pyca_key
