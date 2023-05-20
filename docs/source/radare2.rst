.. testsetup:: *

    from pwn import *
    context.arch = 'amd64'
    context.terminal = [os.path.join(os.path.dirname(pwnlib.__file__), 'gdb_faketerminal.py')]

:mod:`pwnlib.radare2` --- Working with Radare2
================================================

.. automodule:: pwnlib.radare2
   :members:
