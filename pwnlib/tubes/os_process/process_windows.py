import os
import sys
import time
import ctypes
import msvcrt
import random
import string
import struct
import socket
import logging
import threading

from windows import *
import windows
import windows.winobject
import windows.winproxy
import windows.native_exec.nativeutils
import windows.generated_def as gdef
from windows.generated_def.winstructs import *
import windows.native_exec.simple_x64 as x64
import windows.debug

try:
    import capstone
    def disasm(data, bitness=64, vma=0):
        """disasm(data, bitness = 64, vma = 0) dissas the data at vma"""
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bitness == 64 else capstone.CS_MODE_32)
        dis = ''
        for i in cs.disasm(data, vma):
            dis += "%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)
        return dis
except ImportError:
    def disasm(data, bitness=64, vma=0):
        raise (NotImplementedError("Capstone module not found"))

try:
    import keystone

    def asm(code, bitness=64, vma=0):
        """asm(code, bitness = 64, vma = 0) assembles the assembly code at vma"""
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64 if bitness == 64 else keystone.KS_MODE_32)
        encoding, count = ks.asm(code, vma)
        return encoding
except ImportError:
    def asm(code, bitness=64, vma=0):
        raise (NotImplementedError("Keystone module not found"))

CreatePipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.PHANDLE, gdef.PHANDLE, gdef.LPSECURITY_ATTRIBUTES, gdef.DWORD)
CreatePipeParams = ((1, 'hReadPipe'), (1, 'hReadPipe'), (1, 'lpPipeAttributes'), (1, 'nSize'))


@windows.winproxy.Kernel32Proxy('CreatePipe', deffunc_module=sys.modules[__name__])
def CreatePipe(lpPipeAttributes=None, nSize=0):
    hReadPipe = gdef.HANDLE()
    hWritePipe = gdef.HANDLE()
    CreatePipe.ctypes_function(hReadPipe, hWritePipe, lpPipeAttributes, nSize)
    return hReadPipe.value, hWritePipe.value


PeekNamedPipePrototype = gdef.WINFUNCTYPE(gdef.BOOL, gdef.HANDLE, gdef.LPVOID, gdef.DWORD, gdef.LPDWORD, gdef.LPDWORD,
                                          gdef.LPDWORD)
PeekNamedPipeParams = (
(1, 'hNamedPipe'), (1, 'lpBuffer'), (1, 'nBufferSize'), (1, 'lpBytesRead'), (1, 'lpTotalBytesAvail'),
(1, 'lpBytesLeftThisMessage'))


@windows.winproxy.Kernel32Proxy('PeekNamedPipe', deffunc_module=sys.modules[__name__])
def PeekNamedPipe(hNamedPipe):
    lpTotalBytesAvail = gdef.DWORD()
    PeekNamedPipe.ctypes_function(hNamedPipe, None, 0, None, lpTotalBytesAvail, None)
    return lpTotalBytesAvail.value

def interact(obj, escape=False):
    """Base standard input/ouput interaction with a pipe/socket stolen from pwntools"""
    go = threading.Event()
    go.clear()

    def recv_thread():
        while not go.is_set():
            cur = str(obj.recvall(timeout=200))
            cur = cur.replace('\r\n', '\n')
            if escape:
                cur = cur.encode('string-escape')
                cur = cur.replace('\\n', '\n')  # check bytes
                cur = cur.replace('\\t', '\t')  # check bytes
                cur = cur.replace('\\\\', '\\')  # check bytes
            if cur:
                sys.stdout.buffer.write(bytes(cur.encode()))
                if escape and not cur.endswith(b'\n'):
                    sys.stdout.buffer.write(b'\n')
                sys.stdout.flush()
            go.wait(0.2)

    t = threading.Thread(target=recv_thread)
    t.daemon = True
    t.start()
    try:
        while not go.is_set():
            # Impossible to timeout readline
            # Wait a little and check obj
            go.wait(0.2)
            try:
                obj.check_closed()
                data = sys.stdin.readline()
                if data:
                    obj.send(data)
                else:
                    go.set()
            except EOFError:
                go.set()
    except KeyboardInterrupt:
        go.set()

    while t.is_alive():
        t.join(timeout=0.1)


def interact(obj, escape=False):
    """Base standard input/ouput interaction with a pipe/socket stolen from pwntools"""
    go = threading.Event()
    go.clear()

    def recv_thread():
        while not go.is_set():
            cur = str(obj.recvall(timeout=200))
            cur = cur.replace('\r\n', '\n')
            if escape:
                cur = cur.encode('string-escape')
                cur = cur.replace('\\n', '\n')  # check bytes
                cur = cur.replace('\\t', '\t')  # check bytes
                cur = cur.replace('\\\\', '\\')  # check bytes
            if cur:
                sys.stdout.buffer.write(bytes(cur.encode()))
                if escape and not cur.endswith(b'\n'):
                    sys.stdout.buffer.write(b'\n')
                sys.stdout.flush()
            go.wait(0.2)

    t = threading.Thread(target=recv_thread)
    t.daemon = True
    t.start()
    try:
        while not go.is_set():
            # Impossible to timeout readline
            # Wait a little and check obj
            go.wait(0.2)
            try:
                obj.check_closed()
                data = sys.stdin.readline()
                if data:
                    obj.send(data)
                else:
                    go.set()
            except EOFError:
                go.set()
    except KeyboardInterrupt:
        go.set()

    while t.is_alive():
        t.join(timeout=0.1)


class Pipe(object):
    """Windows pipe support"""

    def __init__(self, bInheritHandle=1):
        attr = SECURITY_ATTRIBUTES()
        attr.lpSecurityDescriptor = 0
        attr.bInheritHandle = bInheritHandle
        attr.nLength = ctypes.sizeof(attr)
        self._rpipe, self._wpipe = CreatePipe(attr)
        self._rh = [h for h in windows.current_process.handles if h.value == self._rpipe][0]
        self._wh = [h for h in windows.current_process.handles if h.value == self._wpipe][0]

        self.timeout = 500  # ms
        self.tick = 40  # ms

    def get_handle(self, mode='r'):
        """get_handle(mode = 'r') returns the 'r'ead / 'w'rite HANDLE of the pipe"""
        if mode and mode[0] == 'w':
            return self._wpipe
        return self._rpipe

    def __del__(self):
        if windows != None:
            windows.winproxy.CloseHandle(self._rpipe)
            windows.winproxy.CloseHandle(self._wpipe)
        else:
            pass

    def number_of_clients(self):
        return max(self._rh.infos.HandleCount, self._wh.infos.HandleCount)

    def select(self):
        """select() returns the number of bytes available to read on the pipe"""
        return PeekNamedPipe(self._rpipe)

    def _read(self, size):
        if size == 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        windows.winproxy.ReadFile(self._rpipe, buffer)
        return buffer.raw

    def read(self, size):
        """read(size) returns the bytes read on the pipe (returned length <= size)"""
        if self.select() < size:
            elapsed = 0
            while elapsed <= self.timeout and self.select() < size:
                time.sleep(float(self.tick) / 1000)
                elapsed += self.tick
        return self._read(min(self.select(), size))

    def write(self, buffer):
        """write(buffer) sends the buffer on the pipe"""
        windows.winproxy.WriteFile(self._wpipe, buffer)


class Remote(object):
    """
        Wrapper for remote connections
            Remote("127.0.0.1", 8888)
    """

    def __init__(self, ip, port, family=socket.AF_INET, type=socket.SOCK_STREAM):
        self.sock = socket.socket(family, type)
        self.ip = ip
        self.port = port
        self.timeout = 500  # ms
        self._default_timeout = 500  # ms
        try:
            self.sock.connect((ip, port))
        except socket.timeout:
            self._closed = True
            logging.error("EOFError: Socket {:s} connection failed".format(self))

        self._closed = False
        self.newline = b"\n"

    def __repr__(self):
        return '<{0} "{1}:{2}" at {3}>'.format(self.__class__.__name__, self.ip, self.port, hex(id(self)))

    def close(self):
        """close() closes the connection"""
        self.sock.close()
        self._closed = True

    def check_closed(self, force_exception=True):
        if self._closed and force_exception:
            raise (EOFError("Socket {:s} closed".format(self)))
        elif self._closed:
            logging.warning("EOFError: Socket {:s} closed".format(self))
        return self._closed

    def get_timeout(self):
        return self._timeout

    def set_timeout(self, timeout):
        if timeout:
            self._timeout = timeout
            self.sock.settimeout(float(timeout) / 1000)
        elif self._timeout != self._default_timeout:
            self.timeout = self._default_timeout

    timeout = property(get_timeout, set_timeout)
    """timeout in ms for read on the socket"""

    def read(self, n, timeout=None, no_warning=False):
        """read(n, timeout = None, no_warning = False) tries to read n bytes on the socket before timeout"""
        if timeout:
            self.timeout = timeout
        buf = ''
        if not self.check_closed(False):
            try:
                buf = self.sock.recv(n)
            except socket.timeout:
                if not no_warning:
                    logging.warning("EOFError: Timeout {:s} - Incomplete read".format(self))
            except socket.error:
                self._closed = True
                if not no_warning:
                    logging.warning("EOFError: Socket {:s} closed".format(self))
        return buf

    def write(self, buf):
        """write(buf) sends the buf to the socket"""
        if not self.check_closed(True):
            try:
                if type(buf) == str:
                    return self.sock.send(bytes(buf.encode()))
                elif type(buf) == bytes:
                    return self.sock.send(buf)
                else:
                    print("error")
            except socket.error:
                self._closed = True
                logging.warning("EOFError: Socket {:s} closed".format(self))

    def send(self, buf):
        """send(buf) sends the buf to the socket"""
        self.write(buf)

    def sendline(self, line):
        """sendline(line) sends the line adding newline to the socket"""
        self.write(line + self.newline)

    def recv(self, n, timeout=None):
        """recv(n, timeout = None) tries to read n bytes on the socket before timeout"""
        return self.read(n, timeout)

    def recvn(self, n, timeout=None):
        """recvn(n, timeout = None) reads exactly n bytes on the socket before timeout"""
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise (EOFError("Timeout {:s} - Incomplete read".format(self)))
        return buf

    def recvall(self, force_exception=False, timeout=None):
        """recvall(force_exception = False, timeout = None) reads all bytes available on the socket before timeout"""
        return self.read(0x100000, timeout, no_warning=True)

    def recvuntil(self, delim, drop=False, timeout=None):
        """recvuntil(delim, drop = False, timeout = None) reads bytes until the delim is present on the socket before timeout"""
        buf = b""
        while delim not in buf:
            buf += self.recvn(1, timeout)
        return buf if not drop else buf[:-len(delim)]

    def recvline(self, keepends=True, timeout=None):
        """recvline(keepends = True, timeout = None) reads one line on the socket before timeout"""
        return self.recvuntil(self.newline, not keepends, timeout)

    def interactive(self, escape=False):
        """interactive(escape = None) allows to interact directly with the socket (escape to show binary content received)"""
        interact(self, escape)

    def interactive2(self):
        """interactive2() with telnetlib"""
        fs = self.sock._sock
        import telnetlib
        t = telnetlib.Telnet()
        t.sock = fs
        t.interact()


class process(windows.winobject.process.WinProcess, windows.debug.Debugger):
    """
        Wrapper for Windows process
            Process(r"C:\Windows\system32\mspaint.exe")
            Process("pwn.exe", CREATE_SUSPENDED)
            Process([r"C:\Windows\system32\cmd.exe", '-c', 'echo', 'test'])
    """

    def __init__(self, cmdline, flags=0, nostdhandles=False):
        self.cmd = cmdline
        self.flags = flags
        self.stdhandles = not nostdhandles
        self.debuggerpath = r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
        self.newline = b"\n"
        self.__imports = None
        self.__symbols = None
        self.__libs = None
        self.__offsets = None

        if self.stdhandles:
            self.stdin = Pipe()
            self.stdout = Pipe()
            # stderr mixed with stdout self.stderr = Pipe()
            self.timeout = 500  # ms
            self._default_timeout = 500  # ms

        if self._create_process() != 0:
            raise (ValueError("CreateProcess failed - Invalid arguments"))
        super().__init__(pid=self.mypid, handle=self.myphandle)
        if flags != CREATE_SUSPENDED:
            self.wait_initialized()

    def check_initialized(self):
        is_init = False
        try:  # Accessing PEB
            self.peb.modules[1]
            is_init = True
        except Exception as e:
            logging.info(e)
            pass
        if not is_init:
            logging.info("Process {0} not initialized ...".format(self))
        return is_init

    def wait_initialized(self):

        while not self.check_initialized():
            print(GetLastError())
            time.sleep(0.50)

    def __del__(self):
        pass
        """"# TODO: Kill the debugger too
        if self.__pid:  # and not self.is_exit():
            self.exit(0)
        # os.close(self.stdin)
        # os.close(self.stdout)"""

    def _create_process(self):
        proc_info = PROCESS_INFORMATION()
        lpStartupInfo = None
        StartupInfo = STARTUPINFOA()
        StartupInfo.cb = ctypes.sizeof(StartupInfo)
        if self.stdhandles:
            StartupInfo.dwFlags = gdef.STARTF_USESTDHANDLES
            StartupInfo.hStdInput = self.stdin.get_handle('r')
            StartupInfo.hStdOutput = self.stdout.get_handle('w')
            StartupInfo.hStdError = self.stdout.get_handle('w')
        lpStartupInfo = ctypes.byref(StartupInfo)
        lpCommandLine = None
        lpApplicationName = self.cmd

        if isinstance(self.cmd, (list,)):
            lpCommandLine = (b" ".join([bytes(a) for a in self.cmd]))
            lpApplicationName = None
        try:
            windows.winproxy.CreateProcessA(lpApplicationName, lpCommandLine=lpCommandLine, bInheritHandles=True,
                                            dwCreationFlags=self.flags, lpProcessInformation=ctypes.byref(proc_info),
                                            lpStartupInfo=lpStartupInfo)
            windows.winproxy.CloseHandle(proc_info.hThread)
            self.mypid = proc_info.dwProcessId
            self.myphandle = proc_info.hProcess
        except Exception as exception:
            self.__pid = None
            self.__phandle = None
            logging.warning("Exception {0}: Process {1} failed to start!".format(exception, self.cmd))
            return -1
        return 0

    def check_exit(self, raise_exc=False):
        if self.is_exit:
            if raise_exc:
                raise (EOFError("Process {0} exited".format(self)))
            else:
                logging.warning("EOFError: Process {0} exited".format(self))

    def check_closed(self, raise_exc=False):
        if self.stdhandles and self.client_count() < 2:
            if raise_exc:
                raise (EOFError("Process {:s} I/O is closed".format(self)))
            else:
                logging.warning("EOFError: Process {:s} I/O is closed".format(self))
            return True
        elif self.stdhandles:
            return False
        else:
            return self.check_exit(raise_exc)

    def client_count(self):
        if not self.stdhandles:
            logging.error("client_count called on process {:s} with no input forwarding".format(self))
            return 0
        return max(self.stdin.number_of_clients(), self.stdout.number_of_clients())

    def get_timeout(self):
        if self.stdhandles:
            return self._timeout
        return -1

    def set_timeout(self, timeout):
        pass
        """if timeout:
            self._timeout = timeout
            if self.stdhandles:
                self.stdin.timeout = timeout
                self.stdout.timeout = timeout
        elif self._timeout != self._default_timeout:
            self.timeout = self._default_timeout"""

    timeout = property(get_timeout, set_timeout)
    """timeout in ms for read on the process stdout (pipe)"""

    def read(self, n, timeout=None, no_warning=False):
        """read(n, timeout = None, no_warning = False) tries to read n bytes on process stdout before timeout"""
        if timeout:
            self.timeout = timeout

        buf = b''
        if self.stdhandles:
            buf = self.stdout.read(n)
            if not no_warning and len(buf) != n:
                logging.warning("EOFError: Timeout {:s} - Incomplete read".format(self))
        self.check_closed()  # but signal it
        return buf

    def write(self, buf):
        """write(buf) sends the buf to the process stdin"""
        if self.stdhandles and not self.check_closed(True):
            return self.stdin.write(buf)

    def send(self, buf):
        """send(buf) sends the buf to the process stdin"""
        self.write(buf)

    def sendline(self, line):
        """sendline(line) sends the line adding newline to the process stdin"""
        self.write(line + self.newline)

    def recv(self, n, timeout=None):
        """recv(n, timeout = None) tries to read n bytes on the process stdout before timeout"""
        return bytes(self.read(n, timeout))

    def recvn(self, n, timeout=None):
        """recvn(n, timeout = None) reads exactly n bytes on the process stdout before timeout"""
        buf = self.read(n, timeout)
        if len(buf) != n:
            raise (EOFError("Timeout {:s} - Incomplete read".format(self)))
        return bytes(buf)

    def recvall(self, force_exception=False, timeout=None):
        """recvall(force_exception = False, timeout = None) reads all bytes available on the process stdout before timeout"""
        return self.read(0x100000, timeout, no_warning=True)

    def recvuntil(self, delim, drop=False, timeout=None):
        """recvuntil(delim, drop = False, timeout = None) reads bytes until the delim is present on the process stdout before timeout"""
        buf = b''
        while delim not in buf:
            buf += self.recvn(1, timeout)
        return buf if not drop else buf[:-len(delim)]

    def recvline(self, keepends=True, timeout=None):
        """recvline(keepends = True, timeout = None) reads one line on the process stdout before timeout"""
        return self.recvuntil(self.newline, not keepends, timeout)

    def interactive(self, escape=False):
        """interactive(escape = None) allows to interact directly with the socket (escape to show binary content received)"""
        interact(self, escape)

    def leak(self, addr, count=1):
        """leak(addr, count = 1) reads count bytes of the process memory at addr"""
        if not self.check_initialized():
            return ''
        try:
            return self.read_memory(addr, count)
        except Exception as e:
            logging.warning("{}: {:s} {}".format(e.__class__.__name__, self, str(e)))
            return ''

    def search(self, pattern, writable=False):
        """search(pattern, writable = False) search pattern in all loaded modules (EXE + DLL) ; returns the addr (0 on error)"""
        if not self.check_initialized():
            return 0
        for module in self.peb.modules:
            try:
                for section in module.pe.sections:
                    if writable and section.Characteristics & gdef.IMAGE_SCN_MEM_WRITE == 0:
                        continue
                    for page in range(section.start, section.start + section.size, 0x1000):
                        try:
                            pos = self.read_memory(page, min(0x1000, (section.start + section.size) - page)).find(
                                pattern)
                            if pos != -1:
                                return page + pos
                        except:
                            pass
            except:
                pass
        return 0

    @property
    def imports(self):
        """imports returns a dict of main EXE imports like {'ntdll.dll': {'Sleep': <IATEntry type - .addr .value>, ...}, ...}"""
        if not self.check_initialized():
            raise Exception("Error: PEB not initialized while getting the imports")
            pass

        pe = self.peb.modules[0].pe
        if not self.__imports:
            pe = self.peb.modules[0].pe
            self.__imports = {dll.lower(): {imp.name: imp for imp in imps} for dll, imps in pe.imports.items() if dll}
        return self.__imports

    def get_import(self, dll, function):
        """get_import(self, dll, function) returns the address of the import dll!function"""
        if self.check_initialized() == False:
            raise Exception("Error: PEB not initialized while getting the imports")
            pass

        pe = self.peb.modules[0].pe
        if dll in pe.imports:
            for imp in pe.imports[dll]:
                if imp.name == function:
                    return imp.addr

        raise Exception("Error: dll ({0}) or function({1}) not found".format(dll, function))

    @property
    def symbols(self):
        """symbols returns a dict of the process exports (all DLL) like {'ntdll.dll': {'Sleep': addr, 213: addr, ...}, ...}"""
        if not self.check_initialized():
            return {}
        if not self.__symbols:
            self.__symbols = {module.pe.export_name.lower(): module.pe.exports for module in self.peb.modules if
                              module.pe.export_name}
        return self.__symbols

    def get_proc_address(self, dll, function):
        """get_proc_address(self, dll, function) returns the address of the dll!function"""
        modules = [m for m in self.peb.modules if m.name == dll]
        if not len(modules):
            return 0
        module = modules[0]
        if not function in module.pe.exports:
            return 0
        return module.pe.exports[function]

    @property
    def libs(self):
        """libs returns a dict of loaded modules with their baseaddr like {'ntdll.dll': 0x123456000, ...}"""
        if not self.check_initialized():
            return {}
        if not self.__libs:
            self.__libs = {module.name.lower(): module.baseaddr for module in self.peb.modules if module.name}
        return self.__libs

    def close(self):
        """close() closes the process"""
        if not self.is_exit:
            self.exit(0)

    def spawn_debugger(self, breakin=True, dbg_cmd=None):
        """spawn_debugger(breakin = True, dbg_cmd = None) spawns Windbg (self.debuggerpath) to debug the process"""
        cmd = [self.debuggerpath, '-p', str(self.pid)]
        if not breakin:
            cmd.append('-g')
        if dbg_cmd:
            cmd.append('-c')
            cmd.append(dbg_cmd)
        self.debugger = process(cmd, nostdhandles=True)
        # Give time to the debugger
        time.sleep(1)