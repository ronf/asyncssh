# Copyright (c) 2015 by Ron Frederick <ronf@timeheart.net>.
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

import os
import subprocess
import tempfile
import unittest


class TempDirTestCase(unittest.TestCase):
    """Unit test class which operates in a temporary directory"""

    tempdir = None

    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        os.chdir(cls.tempdir.name)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()


def run(cmd):
    """Run a shell commands and return the output"""

    try:
        return subprocess.check_output(cmd, shell=True,
                                       stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc: # pragma: no cover
        print(exc.output.decode())
        raise
