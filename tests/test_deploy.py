#!/usr/bin/env python3
"""Deployment checks; never installs a root service or changes ~/.ssh.

All persistent-output tests use a private directory below the current user's
home, since the installer deliberately rejects writable output ancestors.
The genuine SSH check uses an isolated unprivileged loopback sshd.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import venv

import test_bridge


PACKAGE = Path(__file__).resolve().parents[1]
DEPLOY = PACKAGE / "deploy.py"


def tree_metadata(path):
    if not path.exists() and not path.is_symlink():
        return None
    entries = [path] + sorted(path.rglob("*")) if path.is_dir() else [path]
    return [(str(p.relative_to(path)) if p != path else ".", p.lstat().st_mode,
             p.lstat().st_size, p.lstat().st_mtime_ns,
             os.readlink(p) if p.is_symlink() else None) for p in entries]


def owned_test_runtime(base):
    """Use real user-owned executables even in UID-remapped test containers."""
    runtime = base / "test-runtime"
    venv.EnvBuilder(with_pip=False, symlinks=False).create(runtime)
    tools = base / "test-tools"
    tools.mkdir(mode=0o700)
    if shutil.which("sshd"):
        shutil.copy2(Path(shutil.which("sshd")).resolve(), tools / "sshd")
    environment = dict(os.environ)
    environment["PATH"] = str(tools) + os.pathsep + environment.get("PATH", "")
    return runtime / "bin" / "python3", environment


def cli(arguments, timeout=30, python=None, environment=None):
    return subprocess.run([str(python or sys.executable), str(DEPLOY)] + list(arguments),
                          capture_output=True, text=True, timeout=timeout, env=environment)


class DeployLauncher(unittest.TestCase):
    def test_old_python_on_path_falls_back_to_a_supported_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            (bin_dir / "dirname").symlink_to(shutil.which("dirname"))
            old = bin_dir / "python3"
            old.write_text("#!/bin/sh\nexit 1\n")
            old.chmod(0o755)
            command = [shutil.which("bash"), str(PACKAGE / "deploy.sh")]
            env = dict(os.environ, PATH=directory)

            missing = subprocess.run(command + ["server", "--help"], env=env,
                                     capture_output=True, text=True)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("Python 3.9 or newer", missing.stderr)

            (bin_dir / "python3.11").symlink_to(sys.executable)
            for override in ([], ["--python", sys.executable]):
                with self.subTest(override=override):
                    result = subprocess.run(command + override + ["server", "--help"], env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--public-key", result.stdout)


class LiveNodes(unittest.TestCase):
    def test_nodes_lists_recent_heartbeats_and_skips_stale_or_invalid_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            share = Path(directory)
            now = time.time()
            for name, timestamp in (("gpu01", now), ("gpu02", now - 30), ("gpu03", now + 300)):
                node = share / name
                node.mkdir()
                (node / "server.json").write_text(json.dumps({"node": name, "time": timestamp,
                    "protocol": 1, "boot": "a" * 32, "ssh_port": 2222}))
            (share / "broken").mkdir()
            (share / "broken" / "server.json").write_text("invalid JSON")

            command = ["nodes", "--share-root", str(share)]
            for flags, expected in (([], ["gpu01"]), (["--max-age", "60"], ["gpu01", "gpu02"])):
                with self.subTest(flags=flags):
                    result = cli(command + flags)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    nodes = [line.split("\t")[0] for line in result.stdout.splitlines()[1:]]
                    self.assertEqual(nodes, expected)
                    self.assertIn("skipping node broken", result.stderr)

            (share / "gpu01" / "server.json").unlink()
            result = cli(command)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no live nodes found", result.stderr)


class PythonOwnerOverride(unittest.TestCase):
    def test_server_accepts_only_the_explicit_python_owner(self):
        import contextlib
        import deploy
        import io

        data = Path("/sharedfs-ssh-test-data")
        python = str(data / "python3")
        owner = os.geteuid() + 1
        arguments = [str(DEPLOY), "server", "--dry-run", "--node", "gpu01", "--share-root", str(PACKAGE),
                     "--public-key", "unused", "--state-dir", "/sharedfs-ssh-test-state", "--pam", "no",
                     "--service-manager", "none"]
        original_lstat = Path.lstat
        for flags, permissions, sshd, error in (
            ([], 0o755, "/sharedfs-ssh-test-bin/sshd", "Python (%s): Local installation path has an untrusted owner" % python),
            (["--trust-python-owner", str(owner + 1)], 0o755, "/sharedfs-ssh-test-bin/sshd", "untrusted owner"),
            (["--trust-python-owner", "trusted-user"], 0o755, "/sharedfs-ssh-test-bin/sshd", None),
            (["--trust-python-owner", str(owner)], 0o775, "/sharedfs-ssh-test-bin/sshd", "group/world writable"),
            (["--trust-python-owner", str(owner)], 0o755, str(data / "sshd"), "sshd (%s): Local installation path has an untrusted owner" % (data / "sshd")),
        ):
            def lstat(path):
                if path == data:
                    return SimpleNamespace(st_uid=owner, st_mode=stat.S_IFDIR | permissions)
                return original_lstat(path)

            with self.subTest(flags=flags, permissions=permissions, sshd=sshd), \
                 mock.patch.object(sys, "argv", arguments + flags), \
                 mock.patch.object(sys, "platform", "linux"), \
                 mock.patch.object(sys, "executable", python), \
                 mock.patch.object(Path, "lstat", lstat), \
                 mock.patch.object(deploy, "validate_public_key"), \
                 mock.patch.object(deploy, "executable", return_value=sshd), \
                 mock.patch.object(deploy.pwd, "getpwnam", return_value=SimpleNamespace(pw_dir="/root", pw_uid=owner)), \
                 mock.patch.object(deploy.os, "umask"), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(deploy.main(), 0 if error is None else 1, stderr.getvalue())
                if error is None:
                    self.assertIn(python, stdout.getvalue())
                else:
                    self.assertIn(error, stderr.getvalue())


class DefaultConfigMerge(unittest.TestCase):
    def test_repairs_missing_markers_and_collapses_duplicate_blocks(self):
        import deploy

        old = deploy.MARKER + "\n\nHost gpu01\n    HostName gpu01\n"
        new = old + "\nHost gpu02\n    HostName gpu02\n"
        block = deploy.merge_default_config("", old).replace("\n", "\r\n")
        personal = "# user configuration\r\nHost other\r\n    HostName example.org"
        for damaged, preserved in (
            (block.replace(deploy.BLOCK_BEGIN + "\r\n", "") + personal, personal),
            (block.replace(deploy.BLOCK_END + "\r\n", "") + personal, personal),
            (block + personal + "\r\n" + block, personal + "\r\n"),
        ):
            with self.subTest(config=damaged):
                merged = deploy.merge_default_config(damaged, new, previous_config=old)
                self.assertEqual(merged.count(deploy.BLOCK_BEGIN), 1)
                self.assertEqual(merged.count(deploy.BLOCK_END), 1)
                self.assertIn(new, merged)
                self.assertEqual(merged.partition(deploy.BLOCK_END + "\n")[2], preserved)
                self.assertEqual(deploy.merge_default_config(merged, new), merged)

    def test_rejects_missing_marker_when_body_contains_unrecognized_settings(self):
        import deploy

        old = deploy.MARKER + "\n\nHost gpu01\n    HostName gpu01\n"
        damaged = deploy.merge_default_config("", old).replace(deploy.BLOCK_END + "\n", "")
        damaged = damaged.replace("\nHost *\n", "\n    Port 2200\n\nHost *\n")
        with self.assertRaisesRegex(deploy.DeployError, "BEGIN at line 1"):
            deploy.merge_default_config(damaged, old, previous_config=old)


class DeploymentValidation(unittest.TestCase):
    def setUp(self):
        if not DEPLOY.exists():
            raise unittest.SkipTest("deploy.py has not been installed beside the tests")
        if not shutil.which("ssh-keygen"):
            raise unittest.SkipTest("ssh-keygen is required")
        self.temp = tempfile.TemporaryDirectory(prefix="sharedfs-deploy-test-", dir=Path.home())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.python, self.environment = owned_test_runtime(self.base)
        self.share = self.base / "share with spaces"
        self.share.mkdir()
        self.identity = self.base / "client identity"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(self.identity)], check=True)
        self.host_fingerprint = subprocess.check_output(
            ["ssh-keygen", "-l", "-f", str(self.identity) + ".pub"], text=True).split()[1]
        spec = importlib.util.spec_from_file_location("deploy_under_test", DEPLOY)
        self.deploy = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.deploy
        spec.loader.exec_module(self.deploy)

    def run_cli(self, arguments):
        return cli(arguments, python=self.python, environment=self.environment)

    def server_args(self):
        return ["server", "--share-root", str(self.share), "--node", "gpu01",
                "--public-key", str(self.identity) + ".pub", "--login-user", "root",
                "--state-dir", str(self.base / "server state"),
                "--service-manager", "none"]

    def client_args(self, config=None):
        return ["client", "--share-root", str(self.share), "--node", "gpu01",
                "--login-user", test_bridge.pwd.getpwuid(os.getuid()).pw_name,
                "--identity-file", str(self.identity),
                "--host-public-key", str(self.identity) + ".pub",
                "--host-fingerprint", self.host_fingerprint,
                "--config-dir", str(config or self.base / "client config"),
                "--bin-dir", str(self.base / "client bin")]

    def test_dry_run_server_and_client_leave_files_unchanged(self):
        before = tree_metadata(self.base)
        ssh_before = tree_metadata(Path.home() / ".ssh")
        for arguments in (self.server_args(), self.client_args()):
            with self.subTest(role=arguments[0]):
                result = self.run_cli(arguments + ["--dry-run"])
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertEqual(tree_metadata(self.base), before)
                self.assertEqual(tree_metadata(Path.home() / ".ssh"), ssh_before)

    def test_server_install_requires_root_before_writing(self):
        if os.geteuid() == 0:
            self.skipTest("This guard test must run as an ordinary user")
        before = tree_metadata(self.base)
        result = self.run_cli(self.server_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(tree_metadata(self.base), before)

    def test_public_key_validation_rejects_private_and_malformed_inputs(self):
        valid = self.deploy.validate_public_key(Path(str(self.identity) + ".pub"))
        self.assertTrue(valid)
        malformed = self.base / "malformed.pub"
        malformed.write_text("ssh-ed25519 NOT_VALID_BASE64\n")
        options = self.base / "options.pub"
        options.write_text('command="touch SHOULD_NOT_RUN" ' +
                           Path(str(self.identity) + ".pub").read_text())
        multiple = self.base / "multiple.pub"
        multiple.write_text(Path(str(self.identity) + ".pub").read_text() * 2)
        for path in (self.identity, malformed, options, multiple):
            with self.subTest(name=path.name), self.assertRaises(self.deploy.DeployError):
                self.deploy.validate_public_key(path)
        self.assertFalse((self.base / "SHOULD_NOT_RUN").exists())

    def test_output_symlink_and_injection_are_rejected_without_writes(self):
        target = self.base / "real-output"
        target.mkdir()
        link = self.base / "linked-output"
        link.symlink_to(target, target_is_directory=True)
        variants = [self.client_args(config=link),
                    self.client_args(config=self.base / "client$(touch injected)")]
        injected_node = self.client_args()
        injected_node[injected_node.index("--node") + 1] = "gpu01\nHost *"
        variants.append(injected_node)
        before = tree_metadata(self.base)
        for arguments in variants:
            with self.subTest(arguments=arguments):
                result = self.run_cli(arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(tree_metadata(self.base), before)

    def test_nonfinite_timing_and_wrong_host_fingerprint_write_nothing(self):
        mismatch = self.client_args()
        mismatch[mismatch.index("--host-fingerprint") + 1] = "SHA256:" + "A" * 43
        before = tree_metadata(self.base)
        for arguments in (self.client_args() + ["--poll", "nan"], mismatch):
            with self.subTest(arguments=arguments):
                result = self.run_cli(arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(tree_metadata(self.base), before)

    def test_default_ssh_config_preserves_existing_entries_and_updates_managed_hosts(self):
        home = self.base / "home"
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(parents=True, mode=0o700)
        config = ssh_dir / "config"
        original = "Host *\n    User existing-user\n\nHost other\n    HostName example.org\n"
        config.write_text(original)
        config.chmod(0o600)
        env = dict(self.environment, HOME=str(home))
        args = self.client_args() + ["--use-default-ssh-config"]
        dry = cli(args + ["--dry-run"], python=self.python, environment=env)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(config.read_text(), original)
        for _ in range(2):
            result = cli(args, python=self.python, environment=env)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(config.read_text().count(self.deploy.BLOCK_BEGIN), 1)
        self.assertTrue(config.read_text().endswith(original))
        self.assertFalse((self.base / "client config" / "ssh_config").exists())
        config.write_text(config.read_text().replace(self.deploy.BLOCK_END, "  " + self.deploy.BLOCK_END + "\t"))
        second = args[:]
        second[second.index("--node") + 1] = "gpu02"
        result = cli(second, python=self.python, environment=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Host gpu01", config.read_text())
        self.assertIn("Host gpu02", config.read_text())
        self.assertTrue(config.read_text().endswith(original))
        for node in ("gpu01", "gpu02"):
            result = subprocess.run(["ssh", "-G", "-F", str(config), node],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("user " + test_bridge.pwd.getpwuid(os.getuid()).pw_name + "\n", result.stdout)
            self.assertIn("proxycommand ", result.stdout)
            self.assertIn("hostkeyalias sharedfs-ssh-" + node + "\n", result.stdout)

    def test_malformed_default_config_block_is_rejected(self):
        with self.assertRaises(self.deploy.DeployError):
            self.deploy.merge_default_config(self.deploy.BLOCK_BEGIN + "\n", "Host gpu01\n")

    def test_host_key_generation_is_idempotent_and_config_avoids_home(self):
        state = self.base / "server state"
        state.mkdir(mode=0o700)
        self.deploy.ensure_host_key(state)
        first = {p.name: p.read_bytes() for p in state.iterdir() if p.is_file()}
        self.assertTrue(first, "No host keys generated")
        self.deploy.ensure_host_key(state)
        second = {p.name: p.read_bytes() for p in state.iterdir() if p.is_file()}
        self.assertEqual(second, first, "Reapplying deployment regenerated host keys")
        key = self.deploy.validate_public_key(Path(str(self.identity) + ".pub"))
        authorized = state / "authorized_keys"
        self.assertTrue(self.deploy.append_authorized_key(authorized, key))
        first_authorized = authorized.read_bytes()
        self.assertFalse(self.deploy.append_authorized_key(authorized, key))
        self.assertEqual(authorized.read_bytes(), first_authorized)
        config = self.deploy.render_sshd_config(state, "root", 22222, "no")
        self.assertNotIn(".ssh", config)
        self.assertIn("AuthorizedKeysFile", config)
        self.assertIn("127.0.0.1", config)
        self.assertIn("PasswordAuthentication no", config)
        self.assertIn("PermitRootLogin prohibit-password", config)
        self.assertIn("22222", config)
        config_path = state / "sshd_config"
        config_path.write_text(config)
        if shutil.which("sshd"):
            checked = subprocess.run([shutil.which("sshd"), "-t", "-f", str(config_path)],
                                     capture_output=True, text=True, timeout=15)
            self.assertEqual(checked.returncode, 0, checked.stderr)


class GeneratedClientIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DEPLOY.exists():
            raise unittest.SkipTest("deploy.py unavailable")
        cls.fixture = test_bridge.BridgeIntegration
        cls.fixture.setUpClass()
        cls.addClassCleanup(cls.fixture.doClassCleanups)
        cls.temp = tempfile.TemporaryDirectory(prefix="sharedfs-client-test-", dir=Path.home())
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        cls.python, cls.environment = owned_test_runtime(cls.output)
        # Exercise the generated dedicated sshd configuration as the ordinary
        # test user, without invoking the privileged installation workflow.
        spec = importlib.util.spec_from_file_location("generated_deploy", DEPLOY)
        deploy = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = deploy
        spec.loader.exec_module(deploy)
        cls.server_state = cls.output / "server state"
        cls.server_state.mkdir(mode=0o700)
        _, _, fingerprint = deploy.ensure_host_key(cls.server_state)
        cls.host_fingerprint = fingerprint.split()[1]
        key = deploy.validate_public_key(cls.fixture.base / "identity.pub")
        deploy.append_authorized_key(cls.server_state / "authorized_keys", key)
        configuration = deploy.render_sshd_config(cls.server_state, cls.fixture.user,
                                                  cls.fixture.port, "no")
        server_config = cls.server_state / "sshd_config"
        server_config.write_text(configuration)
        test_bridge.stop(cls.fixture.sshd)
        cls.generated_log = open(cls.server_state / "sshd.log", "wb")
        cls.addClassCleanup(cls.generated_log.close)
        cls.generated_sshd = subprocess.Popen([shutil.which("sshd"), "-D", "-e", "-f",
                                              str(server_config)],
                                             stdout=subprocess.DEVNULL, stderr=cls.generated_log)
        cls.addClassCleanup(test_bridge.stop, cls.generated_sshd)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.generated_sshd.poll() is not None:
                raise RuntimeError((cls.server_state / "sshd.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", cls.fixture.port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("Generated sshd configuration failed to listen")

    def test_generated_config_wrapper_idempotence_and_real_ssh(self):
        f = self.fixture
        config_dir = self.output / "client config"
        bin_dir = self.output / "client bin"
        arguments = ["client", "--share-root", str(f.share), "--node", "gpu01",
                     "--login-user", f.user, "--identity-file", str(f.base / "identity"),
                     "--host-public-key", str(self.server_state / "ssh_host_ed25519_key.pub"),
                     "--host-fingerprint", self.host_fingerprint,
                     "--config-dir", str(config_dir), "--bin-dir", str(bin_dir)]
        ssh_before = tree_metadata(Path.home() / ".ssh")
        result = cli(arguments, python=self.python, environment=self.environment)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        ssh_config = config_dir / "ssh_config"
        wrapper = bin_dir / "dssh"
        self.assertTrue(ssh_config.is_file())
        self.assertTrue(wrapper.is_file())
        first = {p.name: p.read_bytes() for p in config_dir.iterdir() if p.is_file()}
        result = cli(arguments, python=self.python, environment=self.environment)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        for name, content in first.items():
            self.assertEqual((config_dir / name).read_bytes(), content)
        result = subprocess.run([str(wrapper), "gpu01", "printf GENERATED_CLIENT; exit 9"],
                                input=b"", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertEqual(result.stdout, b"GENERATED_CLIENT")
        self.assertEqual(tree_metadata(Path.home() / ".ssh"), ssh_before)
        # Adding a second node must preserve the first profile and known-host pin.
        second_arguments = arguments[:]
        second_arguments[second_arguments.index("--node") + 1] = "gpu02"
        result = cli(second_arguments, python=self.python, environment=self.environment)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        rendered = ssh_config.read_text()
        self.assertIn("Host gpu01", rendered)
        self.assertIn("Host gpu02", rendered)
        result = subprocess.run(["ssh", "-F", str(ssh_config), "-o", "BatchMode=yes",
                                 "gpu01", "printf PROFILE_PRESERVED"],
                                input=b"", capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"PROFILE_PRESERVED")
        benchmark = PACKAGE / "benchmark.py"
        if benchmark.exists():
            result = subprocess.run([sys.executable, str(benchmark), "--config", str(ssh_config),
                                     "--host", "gpu01", "--samples", "3", "--warmup", "1",
                                     "--label", "local-directory integration check"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report["samples"], 3)
            self.assertGreater(report["setup_ms"], 0)
            self.assertGreater(report["roundtrip_ms"]["median"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
