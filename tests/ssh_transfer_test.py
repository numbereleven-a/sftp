"""Run the production SSH client against a disposable loopback SSH/SFTP peer.

Requires Paramiko and a POSIX shell (including BusyBox for Windows). No saved
profiles, real credentials, system services, or remote machines are used.
"""
import argparse
import logging
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import tempfile
import threading
import time
import shutil

import paramiko

# Transport shutdown can race a socket close after a successful test. Report
# failures through the client exit status rather than Paramiko's stderr logger.
logging.getLogger("paramiko").addHandler(logging.NullHandler())
logging.getLogger("paramiko").propagate = False


class Files(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, root, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = root
        self.modes = server.modes

    def local(self, path):
        result = (self.root / path.lstrip("/")).resolve()
        if not result.is_relative_to(self.root):
            raise PermissionError()
        return result

    def stat(self, path):
        if path.endswith("/denied.bin"):
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            value = paramiko.SFTPAttributes.from_stat(self.local(path).stat())
            value.st_mode = self.modes.get(path, value.st_mode)
            if path.endswith("/short.bin"):
                value.st_size = 100
            return value
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    lstat = stat

    def canonicalize(self, path):
        return "/" + path.lstrip("/") if path != "." else "/"

    def open(self, path, flags, attr):
        try:
            descriptor = os.open(self.local(path), flags, 0o600)
            handle = paramiko.SFTPHandle(flags)
            stream = os.fdopen(descriptor, "r+b" if flags & os.O_RDWR else "wb" if flags & os.O_WRONLY else "rb")
            handle.readfile = stream
            handle.writefile = stream
            return handle
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def chattr(self, path, attr):
        try:
            self.local(path).stat()
            if attr.st_mode is not None:
                self.modes[path] = stat.S_IFREG | attr.st_mode
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def remove(self, path):
        try:
            self.local(path).unlink()
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

    def rename(self, source, target):
        try:
            os.replace(self.local(source), self.local(target))
            return paramiko.SFTP_OK
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)


def receive_line(channel):
    result = b""
    while not result.endswith(b"\n"):
        byte = channel.recv(1)
        if not byte:
            raise EOFError()
        result += byte
    return result


class Peer(paramiko.ServerInterface):
    def __init__(self, root, shell):
        self.root = root
        self.shell = shell
        self.modes = {}

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("synthetic", "synthetic-pass") else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, channel_id):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.run_shell, args=(channel, None), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        command = command.decode("utf-8")
        if command.startswith("scp "):
            threading.Thread(target=self.scp, args=(channel, command), daemon=True).start()
        else:
            threading.Thread(target=self.run_shell, args=(channel, command), daemon=True).start()
        return True

    def run_shell(self, channel, command):
        env = os.environ.copy()
        env["PATH"] = str(self.shell.parent) + os.pathsep + env["PATH"]
        process = subprocess.Popen([str(self.shell), "-c", command] if command else [str(self.shell)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=self.root, env=env, creationflags=subprocess.CREATE_NO_WINDOW)

        def input_stream():
            try:
                while data := channel.recv(4096):
                    process.stdin.write(data)
                    process.stdin.flush()
            except (OSError, EOFError):
                pass
            finally:
                process.stdin.close()

        def output_stream(stream, send):
            try:
                while data := stream.read1(4096):
                    send(data)
            except (OSError, EOFError):
                pass

        threading.Thread(target=input_stream, daemon=True).start()
        output = threading.Thread(target=output_stream, args=(process.stdout, channel.sendall), daemon=True)
        error = threading.Thread(target=output_stream, args=(process.stderr, channel.sendall_stderr), daemon=True)
        output.start()
        error.start()
        code = process.wait()
        output.join()
        error.join()
        try:
            channel.send_exit_status(code)
            channel.shutdown_write()
            channel.close()
        except (OSError, EOFError):
            pass

    def scp(self, channel, command):
        try:
            arguments = shlex.split(command)
            candidate = Path(arguments[-1])
            path = candidate if candidate.drive else self.root / arguments[-1].lstrip("/")
            if not (path.resolve().is_relative_to(self.root) or
                    path.resolve().is_relative_to(self.root.parent / "shell")):
                raise PermissionError()
            if "t" in arguments[1]:
                channel.sendall(b"\0")
                header = receive_line(channel).split(b" ", 2)
                size = int(header[1])
                channel.sendall(b"\0")
                data = b""
                while len(data) < size:
                    chunk = channel.recv(min(size - len(data), 65536))
                    if not chunk:
                        raise EOFError()
                    data += chunk
                if channel.recv(1) != b"\0":
                    raise EOFError()
                if path.name == "scp-fail.bin":
                    channel.sendall(b"\1synthetic disk full\n")
                else:
                    path.write_bytes(data)
                    channel.sendall(b"\0")
            else:
                if channel.recv(1) != b"\0":
                    raise EOFError()
                data = path.read_bytes()
                if "p" in arguments[1]:
                    channel.sendall(b"T1700000000 0 1700000000 0\n")
                    if channel.recv(1) != b"\0":
                        raise EOFError()
                channel.sendall(b"C0644 " + str(len(data)).encode() + b" file.bin\n")
                if channel.recv(1) != b"\0":
                    raise EOFError()
                channel.sendall(data + b"\0")
                channel.recv(1)
            channel.send_exit_status(0)
        except (OSError, EOFError, ValueError):
            pass
        finally:
            channel.close()


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("client", type=Path)
    parser.add_argument("--shell", type=Path, required=True)
    parser.add_argument("--php", type=Path)
    args = parser.parse_args()
    # The ephemeral peer key remains in memory throughout this test.
    key = paramiko.RSAKey.generate(2048)
    with tempfile.TemporaryDirectory(prefix="sftp-loopback-") as temporary:
        root = Path(temporary)
        remote = root / "remote"
        remote.mkdir()
        (remote / "short.bin").write_bytes(b"short")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.2)
        port = listener.getsockname()[1]
        stop = threading.Event()
        transports = []

        def accept_loop():
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                transport = paramiko.Transport(client)
                transport.add_server_key(key)
                transport.set_subsystem_handler("sftp", paramiko.SFTPServer, Files, root=remote)
                transport.start_server(server=Peer(remote, args.shell.resolve()))
                transports.append(transport)

        accept = threading.Thread(target=accept_loop, daemon=True)
        accept.start()
        php = None
        try:
            client_args = [str(args.client.resolve()), str(port), str(root)]
            if args.php:
                php_root = root / "php"
                php_root.mkdir()
                shutil.copyfile(Path(__file__).resolve().parents[1] / "src/agent/sftp.php", php_root / "sftp.php")
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", 0))
                    php_port = probe.getsockname()[1]
                env = os.environ.copy()
                env["TC_SFTP_AGENT_PSK"] = "synthetic-pass"
                php = subprocess.Popen([str(args.php), "-S", f"127.0.0.1:{php_port}", "-t", str(php_root)],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
                for _ in range(100):
                    try:
                        with socket.create_connection(("127.0.0.1", php_port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.05)
                client_args.append(str(php_port))
            result = subprocess.run(client_args, timeout=180)
            return result.returncode
        finally:
            if php:
                php.terminate()
                php.wait(timeout=10)
            stop.set()
            accept.join()
            listener.close()
            for transport in transports:
                transport.close()


if __name__ == "__main__":
    raise SystemExit(main())
