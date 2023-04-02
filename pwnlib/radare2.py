# -*- coding: utf-8 -*-
"""
During exploit development, it is frequently useful to debug the
target binary under Radare2.

Pwntools makes this easy-to-do with a handful of helper routines, designed
to make your exploit-debug-update cycles much faster.

Useful Functions
----------------

- :func:`attach` - Attach to an existing process
- :func:`debug` - Start a new process under a debugger, stopped at the first instruction
- :func:`debug_shellcode` - Build a binary with the provided shellcode, and start it under a debugger

Debugging Tips
--------------

The :func:`attach` and :func:`debug` functions will likely be your bread and
butter for debugging.

Both allow you to provide a script to pass to Radare2 when it is started, so that
it can automatically set your breakpoints.

Attaching to Processes
~~~~~~~~~~~~~~~~~~~~~~

To attach to an existing process, just use :func:`attach`.  It is surprisingly
versatile, and can attach to a :class:`.process` for simple
binaries, or will automatically find the correct process to attach to for a
forking server, if given a :class:`.remote` object.

Spawning New Processes
~~~~~~~~~~~~~~~~~~~~~~

Attaching to processes with :func:`attach` is useful, but the state the process
is in may vary.  If you need to attach to a process very early, and debug it from
the very first instruction (or even the start of ``main``), you instead should use
:func:`debug`.

When you use :func:`debug`, the return value is a :class:`.tube` object
that you interact with exactly like normal.

Using Radare2 Python API
~~~~~~~~~~~~~~~~~~~~~~~~

GDB provides Python API, which is documented at
https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html. Pwntools allows you
to call it right from the exploit, without having to write a gdbscript. This is
useful for inspecting program state, e.g. asserting that leaked values are
correct, or that certain packets trigger a particular code path or put the heap
in a desired state.

Pass ``api=True`` to :func:`attach` or :func:`debug` in order to enable GDB
Python API access. Pwntools will then connect to GDB using RPyC library:
https://rpyc.readthedocs.io/en/latest/.

At the moment this is an experimental feature with the following limitations:

- Only Python 3 is supported.

  Well, technically that's not quite true. The real limitation is that your
  GDB's Python interpreter major version should be the same as that of
  Pwntools. However, most GDBs use Python 3 nowadays.

  Different minor versions are allowed as long as no incompatible values are
  sent in either direction. See
  https://rpyc.readthedocs.io/en/latest/install.html#cross-interpreter-compatibility
  for more information.

  Use

  ::

      $ gdb -batch -ex 'python import sys; print(sys.version)'

  in order to check your GDB's Python version.
- If your GDB uses a different Python interpreter than Pwntools (for example,
  because you run Pwntools out of a virtualenv), you should install ``rpyc``
  package into its ``sys.path``. Use

  ::

      $ gdb -batch -ex 'python import rpyc'

  in order to check whether this is necessary.
- Only local processes are supported.
- It is not possible to tell whether ``gdb.execute('continue')`` will be
  executed synchronously or asynchronously (in gdbscripts it is always
  synchronous). Therefore it is recommended to use either the explicitly
  synchronous :func:`pwnlib.gdb.Gdb.continue_and_wait` or the explicitly
  asynchronous :func:`pwnlib.gdb.Gdb.continue_nowait` instead.

Tips and Troubleshooting
------------------------

``NOPTRACE`` magic argument
~~~~~~~~~~~~~~~~~~~~~~~~~~~

It's quite cumbersom to comment and un-comment lines containing `attach`.

You can cause these lines to be a no-op by running your script with the
``NOPTRACE`` argument appended, or with ``PWNLIB_NOPTRACE=1`` in the environment.

::

    $ python exploit.py NOPTRACE
    [+] Starting local process '/bin/bash': Done
    [!] Skipping debug attach since context.noptrace==True
    ...

Kernel Yama ptrace_scope
~~~~~~~~~~~~~~~~~~~~~~~~

The Linux kernel v3.4 introduced a security mechanism called ``ptrace_scope``,
which is intended to prevent processes from debugging eachother unless there is
a direct parent-child relationship.

This causes some issues with the normal Pwntools workflow, since the process
hierarchy looks like this:

::

    python ---> target
           `--> gdb

Note that ``python`` is the parent of ``target``, not ``gdb``.

In order to avoid this being a problem, Pwntools uses the function
``prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)``.  This disables Yama
for any processes launched by Pwntools via :class:`.process` or via
:meth:`.ssh.process`.

Older versions of Pwntools did not perform the ``prctl`` step, and
required that the Yama security feature was disabled systemwide, which
requires ``root`` access.

Member Documentation
===============================
"""

import six
import os
import tempfile
from pwnlib.context import LocalContext, context
from pwnlib.util import misc
from pwnlib.util import proc
from pwnlib.log import getLogger
from pwnlib import tubes


log = getLogger(__name__)



def binary():
    """binary() -> str
    Returns:
        str: Path to the appropriate ``radare2`` binary to use.
    Example:
        >>> radare2.binary() # doctest: +SKIP
        '/usr/local/bin/r2'
    """
    radare2 = misc.which('radare2')

    if not radare2:
        log.error('radare2 is not installed\n'
                  '$ git clone https://github.com/radareorg/radare2 ; cd radare2 ; sh sys/install.sh ; cd .. ;')

    return radare2
    

@LocalContext
def attach(target, radare2_script = "", exe = None, radare2_args = None, ssh = None, sysroot = None, api = False):
    r"""
    Start Radare2 in a new terminal and attach to `target`.

    Arguments:
        target: The target to attach to.
        radare2_script(:obj:`str` or :obj:`file`): Radare2 script to run after attaching.
        exe(str): The path of the target binary.
        arch(str): Architechture of the target binary.  If `exe` known Radare2 will
          detect the architechture automatically (if it is supported).
        radare2_args(list): List of additional arguments to pass to Radare2.
        sysroot(str): Set an alternate system root. The system root is used to
            load absolute shared library symbol files. This is useful to instruct
            Radare2 to load a local version of binaries/libraries instead of downloading
            them from the gdbserver, which is faster
        api(bool): Enable access to Radare2 Python API.

    Returns:
        PID of the Radare2 process (or the window which it is running in).
        When ``api=True``, a (PID, :class:`Radare2`) tuple.

    Notes:

        The ``target`` argument is very robust, and can be any of the following:

        :obj:`int`
            PID of a process
        :obj:`str`
            Process name.  The youngest process is selected.
        :obj:`tuple`
            Host, port pair of a listening ``gdbserver``
        :class:`.process`
            Process to connect to
        :class:`.sock`
            Connected socket. The executable on the other end of the connection is attached to.
            Can be any socket type, including :class:`.listen` or :class:`.remote`.
        :class:`.ssh_channel`
            Remote process spawned via :meth:`.ssh.process`.
            This will use the Radare2 installed on the remote machine.
            If a password is required to connect, the ``sshpass`` program must be installed.

    Examples:

        Attach to a process by PID

        >>> pid = radare2.attach(1234) # doctest: +SKIP

        Attach to the youngest process by name

        >>> pid = radare2.attach('bash') # doctest: +SKIP

        Attach a debugger to a :class:`.process` tube and automate interaction
        
        >>> io = process('bash')
        >>> pid = radare2.attach(io, radare2_script='''
        ... pd 10 @ main
        ... ''')
        >>> io.recvline()
        b'Hello from process debugger!\n'
        >>> io.sendline(b'echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Using Radare2 Python API:

        .. doctest
           :skipif: six.PY2

            >>> io = process('bash')

            Attach a debugger

            >>> pid, io_radare2 = radare2.attach(io, api=True)

            Force the program to write something it normally wouldn't

            >>> io_radare2.execute('call puts("Hello from process debugger!")')

            Resume the program

            >>> io_radare2.continue_nowait()

            Observe the forced line

            >>> io.recvline()
            b'Hello from process debugger!\n'

            Interact with the program in a regular way

            >>> io.sendline(b'echo Hello from bash && exit')

            Observe the results

            >>> io.recvall()
            b'Hello from bash\n'

        Attach to the remote process from a :class:`.remote` or :class:`.listen` tube,
        as long as it is running on the same machine.

        >>> server = process(['socat', 'tcp-listen:12345,reuseaddr,fork', 'exec:/bin/bash,nofork'])
        >>> sleep(1) # Wait for socat to start
        >>> io = remote('127.0.0.1', 12345)
        >>> sleep(1) # Wait for process to fork
        >>> pid = radare2.attach(io, radare2_script='''
        ... call puts("Hello from remote debugger!")
        ... detach
        ... quit
        ... ''')
        >>> io.recvline()
        b'Hello from remote debugger!\n'
        >>> io.sendline(b'echo Hello from bash && exit')
        >>> io.recvall()
        b'Hello from bash\n'

        Attach to processes running on a remote machine via an SSH :class:`.ssh` process

        >>> shell = ssh('travis', 'example.pwnme', password='demopass')
        >>> io = shell.process(['cat'])
        >>> pid = radare2.attach(io, radare2_script='''
        ... px @ main
        ... ''')
        >>> io.recvline(timeout=5)  # doctest: +SKIP
        b'Hello from ssh debugger!\n'
        >>> io.sendline(b'This will be echoed back')
        >>> io.recvline()
        b'This will be echoed back\n'
        >>> io.close()
    """
    if context.noptrace:
        log.warn_once("Skipping debug attach since context.noptrace==True")
        return

    # enable radare2.attach(p, 'continue')
    if radare2_script and not radare2_script.endswith('\n'):
        radare2_script += '\n'

    # radare2 script to run before `radare2_script`

    # let's see if we can find a pid to attach to
    pid = None
    if   isinstance(target, six.integer_types):
        # target is a pid, easy peasy
        pid = target
    elif isinstance(target, str):
        # pidof picks the youngest process
        pidof = proc.pidof

        if context.os == 'android':
            pidof = adb.pidof

        pids = list(pidof(target))
        if not pids:
            log.error('No such process: %s', target)
        pid = pids[0]
        log.info('Attaching to youngest process "%s" (PID = %d)' %
                 (target, pid))
    elif isinstance(target, tubes.ssh.ssh_channel):
        if not target.pid:
            log.error("PID unknown for channel")

        shell = target.parent

        tmpfile = shell.mktemp()
        radare2_script = b'shell rm %s\n%s' % (tmpfile, packing._need_bytes(radare2_script, 2, 0x80))
        shell.upload_data(radare2_script or b'', tmpfile)

        cmd = ['ssh', '-C', '-t', '-p', str(shell.port), '-l', shell.user, shell.host]
        if shell.password:
            if not misc.which('sshpass'):
                log.error("sshpass must be installed to debug ssh processes")
            cmd = ['sshpass', '-p', shell.password] + cmd
        if shell.keyfile:
            cmd += ['-i', shell.keyfile]
        cmd += ['gdb', '-q', target.executable, str(target.pid), '-x', tmpfile]

        misc.run_in_new_terminal(cmd)
        return
    elif isinstance(target, tubes.sock.sock):
        pids = proc.pidof(target)
        if not pids:
            log.error('Could not find remote process (%s:%d) on this machine' %
                      target.sock.getpeername())
        pid = pids[0]

        # Specifically check for socat, since it has an intermediary process
        # if you do not specify "nofork" to the EXEC: argument
        # python(2640)───socat(2642)───socat(2643)───bash(2644)
        if proc.exe(pid).endswith('/socat') and time.sleep(0.1) and proc.children(pid):
            pid = proc.children(pid)[0]

        # We may attach to the remote process after the fork but before it performs an exec.  
        # If an exe is provided, wait until the process is actually running the expected exe
        # before we attach the debugger.
        t = Timeout()
        with t.countdown(2):
            while exe and os.path.realpath(proc.exe(pid)) != os.path.realpath(exe) and t.timeout:
                time.sleep(0.1)

    elif isinstance(target, tubes.process.process):
        pid = proc.pidof(target)[0]
        exe = exe or target.executable
    elif isinstance(target, tuple) and len(target) == 2:
        host, port = target

        if context.os != 'android':
            pre += 'target remote %s:%d\n' % (host, port)
        else:
            # Android debugging is done over gdbserver, which can't follow
            # new inferiors (tldr; follow-fork-mode child) unless it is run
            # in extended-remote mode.
            pre += 'target extended-remote %s:%d\n' % (host, port)
            pre += 'set detach-on-fork off\n'

        def findexe():
            for spid in proc.pidof(target):
                sexe = proc.exe(spid)
                name = os.path.basename(sexe)
                # XXX: parse cmdline
                if name.startswith('qemu-') or name.startswith('gdbserver'):
                    exe = proc.cmdline(spid)[-1]
                    return os.path.join(proc.cwd(spid), exe)

        exe = exe or findexe()
    elif isinstance(target, elf.corefile.Corefile):
        pre += 'target core "%s"\n' % target.path
    else:
        log.error("don't know how to attach to target: %r", target)
        
        
        

    # if we have a pid but no exe, just look it up in /proc/
    if pid and not exe:
        exe_fn = proc.exe
        if context.os == 'android':
            exe_fn = adb.proc_exe
        exe = exe_fn(pid)

    if not pid and not exe and not ssh:
        log.error('could not find target process')

    radare2_binary = binary()
    cmd = [radare2_binary]

    if radare2_args:
        cmd += radare2_args

    if exe and context.native:
        if not ssh and not os.path.isfile(exe):
            log.error('No such file: %s', exe)
        cmd += ["-d", exe]

    if pid and not context.os == 'android':
        cmd += [str(pid)]
        
    pre = ""

    if context.os == 'android' and pid:
        runner  = _get_runner()
        which   = _get_which()
        gdb_cmd = _gdbserver_args(pid=pid, which=which)
        gdbserver = runner(gdb_cmd)
        port    = _gdbserver_port(gdbserver, None)
        host    = context.adb_host
        pre    += 'target extended-remote %s:%i\n' % (context.adb_host, port)

        # gdbserver on Android sets 'detach-on-fork on' which breaks things
        # when you're trying to debug anything that forks.
        pre += 'set detach-on-fork off\n'

    if api:
        # create a UNIX socket for talking to GDB
        socket_dir = tempfile.mkdtemp()
        socket_path = os.path.join(socket_dir, 'socket')
        bridge = os.path.join(os.path.dirname(__file__), 'gdb_api_bridge.py')

        # inject the socket path and the GDB Python API bridge
        pre = 'python socket_path = ' + repr(socket_path) + '\n' + \
              'source ' + bridge + '\n' + \
              pre

    radare2_script = pre + (radare2_script or '')

    if radare2_script:
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.r2',
                                          delete = False, mode = 'w+')
        log.debug('Wrote radare2 script to %r\n%s', tmp.name, radare2_script)
        radare2_script = 'shell rm %s\n%s' % (tmp.name, radare2_script)

        tmp.write(radare2_script)
        tmp.close()
        cmd += ['-i', tmp.name]

    log.info('running in new terminal: %s', cmd)

    if api:
        # prevent gdb_faketerminal.py from messing up api doctests
        def preexec_fn():
            os.environ['GDB_FAKETERMINAL'] = '0'
    else:
        preexec_fn = None
    gdb_pid = misc.run_in_new_terminal(cmd, preexec_fn = preexec_fn)

    if pid and context.native:
        proc.wait_for_debugger(pid, gdb_pid)

    if not api:
        return gdb_pid

    # connect to the GDB Python API bridge
    from rpyc import BgServingThread
    from rpyc.utils.factory import unix_connect
    if six.PY2:
        retriable = socket.error
    else:
        retriable = ConnectionRefusedError, FileNotFoundError

    t = Timeout()
    with t.countdown(10):
        while t.timeout:
            try:
                conn = unix_connect(socket_path)
                break
            except retriable:
                time.sleep(0.1)
        else:
            # Check to see if RPyC is installed at all in GDB
            rpyc_check = [gdb_binary, '--nx', '-batch', '-ex',
                          'python import rpyc; import sys; sys.exit(123)']

            if 123 != tubes.process.process(rpyc_check).poll(block=True):
                log.error('Failed to connect to GDB: rpyc is not installed')

            # Check to see if the socket ever got created
            if not os.path.exists(socket_path):
                log.error('Failed to connect to GDB: Unix socket %s was never created', socket_path)

            # Check to see if the remote RPyC client is a compatible version
            version_check = [gdb_binary, '--nx', '-batch', '-ex',
                            'python import platform; print(platform.python_version())']
            gdb_python_version = tubes.process.process(version_check).recvall().strip()
            python_version = str(platform.python_version())

            if gdb_python_version != python_version:
                log.error('Failed to connect to GDB: Version mismatch (%s vs %s)',
                           gdb_python_version,
                           python_version)

            # Don't know what happened
            log.error('Failed to connect to GDB: Unknown error')

    # now that connection is up, remove the socket from the filesystem
    os.unlink(socket_path)
    os.rmdir(socket_dir)

    # create a thread for receiving breakpoint notifications
    BgServingThread(conn, callback=lambda: None)

    return gdb_pid, Gdb(conn)
