Contributing to AsyncSSH
========================

Input on AsyncSSH is extremely welcome. Below are some recommendations of
the best ways to contribute.

Asking questions
----------------

If you have a general question about how to use AsyncSSH, you are welcome
to post it to the end-user mailing list at `asyncssh-users@googlegroups.com
<http://groups.google.com/d/forum/asyncssh-users>`_. If you have a question
related to the development of AsyncSSH, you can post it to the development
mailing list at `asyncssh-dev@googlegroups.com
<http://groups.google.com/d/forum/asyncssh-dev>`_.

You are also welcome to use the AsyncSSH `issue tracker
<https://github.com/ronf/asyncssh/issues>`_ to ask questions.

Reporting bugs
--------------

Please use the `issue tracker <https://github.com/ronf/asyncssh/issues>`_
to report any bugs you find. Before creating a new issue, please check the
currently open issues to see if your problem has already been reported.

If you create a new issue, please include the version of AsyncSSH you are
using, information about the OS you are running on and the installed
version of Python and any other libraries that are involved. Please also
include detailed information about how to reproduce the problem, including
any traceback information you were able to collect or other relevant output.
If you have sample code which exhibits the problem, feel free to include
that as well.

If possible, please test against the latest version of AsyncSSH. Also, if
you are testing code in something other than the master branch, it would
be helpful to know if you also see the problem in master.

Requesting feature enhancements
-------------------------------

The `issue tracker <https://github.com/ronf/asyncssh/issues>`_
should also be used to post feature enhancement requests. While I can't
make any promises about what features will be added in the future,
suggestions are always welcome!

Contributing code
-----------------

Before submitting a pull request, please create an issue on the `issue
tracker <https://github.com/ronf/asyncssh/issues>`_ explaining what
functionality you'd like to contribute and how it could be used.
Discussing the approach you'd like to take up front will make it far
more likely I'll be able to accept your changes, or explain what issues
might prevent that before you spend a lot of effort.

If you find a typo or other small bug in the code, you're welcome to
submit a patch without filing an issue first, but for anything larger than
a few lines I strongly recommend coordinating up front.

Any code you submit will need to be provided with a compatible license.
AsyncSSH code is currently released under the `Eclipse Public License
v2.0 <http://www.eclipse.org/legal/epl-2.0/>`_. Before submitting
a pull request, make sure to indicate that you are ok with releasing
your code under this license and how you'd like to be listed in the
contributors list.

Branches
--------

There are two long-lived branches in AsyncSSH at the moment:

* The master branch is intended to contain the latest stable version
  of the code. All official versions of AsyncSSH are released from
  this branch, and each release has a corresponding tag added
  matching its release number. Bug fixes and simple improvements
  may be checked directly into this branch, but most new features
  will be added to the develop branch first.

* The develop branch is intended to contain features for developers
  to test before they are ready to be added to an official release.
  APIs in the develop branch may be subject to change until they
  are migrated back to master, and there's no guarantee of backward
  compatibility in this branch. However, pulling from this branch
  will provide early access to new functionality and a chance to
  influence this functionality before it is released.
