#!/usr/bin/env python3
"""Local integration checks using real OpenSSH; no remote hosts are contacted.

Run on Linux with python3, ssh, ssh-keygen and sshd installed:
    python3 tests/test_bridge.py
Uses temporary keys/configuration, an unprivileged sshd on loopback, and a local
temporary directory standing in for the share. This does not validate a real
NFS/SMB mount's cache consistency or latency.
"""
import concurrent.futures
import os
from pathlib import Path
import pwd
import selectors
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "sharedfs_ssh.py"


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class BridgeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for executable in ("ssh", "ssh-keygen", "sshd"):
            if not shutil.which(executable):
                raise unittest.SkipTest(f"Required executable unavailable: {executable}")
        if not SCRIPT.is_file():
            raise RuntimeError(f"Missing bridge script: {SCRIPT}")
        cls.temp = tempfile.TemporaryDirectory(prefix="sharedfs-ssh-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.share = cls.base / "share"
        cls.share.mkdir()
        cls.user = pwd.getpwuid(os.getuid()).pw_name
        cls.port = unused_port()
        for name in ("host", "identity"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(cls.base / name)], check=True)
        host_key = (cls.base / "host.pub").read_text().split()
        (cls.base / "known_hosts").write_text(
            "gpu01 " + " ".join(host_key[:2]) + "\n"
            "gpu02 " + " ".join(host_key[:2]) + "\n")
        config = cls.base / "sshd_config"
        config.write_text(f"""Port {cls.port}
ListenAddress 127.0.0.1
HostKey {cls.base / 'host'}
PidFile {cls.base / 'sshd.pid'}
AuthorizedKeysFile {cls.base / 'identity.pub'}
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
LogLevel ERROR
Subsystem sftp internal-sftp
""")
        cls.sshd_log = open(cls.base / "sshd.log", "wb")
        cls.addClassCleanup(cls.sshd_log.close)
        cls.sshd = subprocess.Popen(
            [shutil.which("sshd"), "-D", "-e", "-f", str(config)],
            stdout=subprocess.DEVNULL, stderr=cls.sshd_log)
        cls.addClassCleanup(stop, cls.sshd)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.sshd.poll() is not None:
                raise RuntimeError((cls.base / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Temporary sshd failed to listen")
        cls.bridge = cls.start_bridge("gpu01", cls.port)
        cls.addClassCleanup(lambda: stop(cls.bridge))

    @classmethod
    def start_bridge(cls, node, port):
        marker = cls.share / node / "server.json"
        previous = marker.read_bytes() if marker.exists() else None
        log = open(cls.base / f"{node}-bridge-{time.time_ns()}.log", "wb")
        cls.addClassCleanup(log.close)
        process = subprocess.Popen([
            sys.executable, str(SCRIPT), "server", "--root", str(cls.share),
            "--node", node, "--ssh-port", str(port), "--poll", "0.02",
            "--heartbeat", "0.2", "--peer-timeout", "6"],
            stdout=subprocess.DEVNULL, stderr=log)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Bridge exited with {process.returncode}; see {log.name}")
            try:
                if marker.read_bytes() != previous:
                    return process
            except FileNotFoundError:
                pass
            time.sleep(.05)
        stop(process)
        raise RuntimeError(f"Bridge did not publish readiness; see {log.name}")

    @classmethod
    def command(cls, command, node="gpu01", tty=False):
        proxy = shlex.join([
            sys.executable, str(SCRIPT), "client", "--root", str(cls.share),
            "--node", node, "--poll", "0.02", "--heartbeat", "0.2",
            "--peer-timeout", "6", "--connect-timeout", "10"])
        args = ["ssh", "-F", "/dev/null", "-i", str(cls.base / "identity"),
                "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                "-o", "LogLevel=ERROR", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={cls.base / 'known_hosts'}",
                "-o", "ConnectTimeout=15", "-o", f"ProxyCommand={proxy}"]
        if tty:
            args.append("-tt")
        return args + [f"{cls.user}@{node}", command]

    @classmethod
    def run_ssh(cls, command, data=b"", node="gpu01", tty=False, timeout=45):
        return subprocess.run(cls.command(command, node, tty), input=data,
                              capture_output=True, timeout=timeout)

    def test_01_stdout_stderr_and_exit_status(self):
        result = self.run_ssh("printf 'OUT\\n'; printf 'ERR\\n' >&2; exit 7")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(result.stdout, b"OUT\n")
        self.assertEqual(result.stderr, b"ERR\n")

    def test_02_binary_transfer_larger_than_window(self):
        data = os.urandom(5 * 1024 * 1024 + 137)
        result = self.run_ssh("cat", data=data, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, data)

    def test_03_concurrent_sessions(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda i: self.run_ssh(f"printf session-{i}"),
                                    range(4)))
        for i, result in enumerate(results):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"session-{i}".encode())

    def test_04_pty_allocation(self):
        command = "test -t 0 && test -t 1 && printf TTY_OK"
        direct_args = self.command(command, tty=True)
        for i, argument in enumerate(direct_args):
            if argument.startswith("ProxyCommand="):
                direct_args[i] = "ProxyCommand=none"
        direct_args[-2] = f"{self.user}@127.0.0.1"
        direct_args[-2:-2] = ["-o", "HostKeyAlias=gpu01", "-p", str(self.port)]
        direct = subprocess.run(direct_args, input=b"", capture_output=True, timeout=15)
        if direct.returncode != 0 and "chown(/dev/pts/" in (self.base / "sshd.log").read_text():
            self.skipTest("Container prevents test sshd PTY ownership; direct TCP SSH also fails")
        self.assertEqual(direct.returncode, 0, direct.stderr)
        result = self.run_ssh(command, tty=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"TTY_OK", result.stdout)

    def test_05_unavailable_sshd_fails(self):
        bridge = self.start_bridge("gpu02", unused_port())
        try:
            result = self.run_ssh("true", node="gpu02", timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(bridge.poll(), "One failed connection killed the daemon")
        finally:
            stop(bridge)

    def test_06_restart_ends_old_session_and_allows_new(self):
        process = subprocess.Popen(self.command("printf STARTED; exec sleep 30"),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(15), "SSH command never started")
                self.assertEqual(os.read(process.stdout.fileno(), 7), b"STARTED")
            stop(type(self).bridge)
            type(self).bridge = self.start_bridge("gpu01", self.port)
            _, error = process.communicate(timeout=20)
            self.assertNotEqual(process.returncode, 0, error)
            result = self.run_ssh("printf NEW_SESSION")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"NEW_SESSION")
        finally:
            stop(process)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
