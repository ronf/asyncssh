# Copyright (c) 2013 by Ron Frederick <ronf@timeheart.net>.
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

"""Asynchronous function wrapper, for calling functions in a child process"""

import asyncore, socket
from multiprocessing import Process, Pipe

class _AsyncFuncCall(asyncore.file_dispatcher):
    def __init__(self, func, *args, callback, callback_args=(),
                 callback_kwargs={}, **kwargs):
        self._callback = callback
        self._cb_args = callback_args
        self._cb_kwargs = callback_kwargs

        self._pipe, child_pipe = Pipe()

        self._child = Process(target=self._call_func, args=(child_pipe, func,
                                                            args, kwargs))
        self._child.start()

        super().__init__(self._pipe)

    def _call_func(self, pipe, func, args, kwargs):
        try:
            pipe.send(('result', func(*args, **kwargs)))
        except Exception as exc:
            pipe.send(('exception', exc))

    def readable(self):
        return True

    def writable(self):
        return False

    def handle_read(self):
        rtype, result = self._pipe.recv()
        self._child.join()
        self.close()

        self._callback(rtype, result, *self._cb_args, **self._cb_kwargs)

class AsyncFunc:
    """Asynchronous function wrapper

       This class can be wrapped around an arbitrary Python function to
       turn it into something which can be executed in a child process
       to avoid blocking the asyncore event loop. The wrapped function
       always returns immediately and triggers a callback from the
       event loop when the function returns or raises an exception.

       The wrapped function takes all of the arguments of the original
       function plus three more:

           * callback: The function to call when the operation completes
           * callback_args: Additional positional arguments for callback
           * callback_kwargs: Additional keyword arguments for callback

       When the callback is called, its first two positional arguments
       are a result type ('result' or 'exception') and then the result
       itself or the exception which was raised. Other arguments can
       also be passed via callback_args and callback_kwargs.

    """

    def __init__(self, func):
        self._func = func

    def __call__(self, *args, **kwargs):
        _AsyncFuncCall(self._func, *args, **kwargs)

getaddrinfo = AsyncFunc(socket.getaddrinfo)
