#!/usr/bin/env python3
"""Validate timing configuration without starting services or writing files."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "sharedfs_ssh.py"
spec = importlib.util.spec_from_file_location("bridge_under_test", SCRIPT)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

deploy_spec = importlib.util.spec_from_file_location("deploy_edit_test", SCRIPT.parent / "deploy.py")
deploy = importlib.util.module_from_spec(deploy_spec)
deploy_spec.loader.exec_module(deploy)


class EditConfiguration(unittest.TestCase):
    def test_edit_restores_saved_options_and_only_changes_requested_values(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "sshd_config").write_text(deploy.MARKER + "\nUsePAM yes\n")
            manifest = {"node": "gpu01", "login_user": "root", "manager": "supervisor",
                        "share_gid": 42, "bridge_cmd": ["python3", "bridge.py", "server",
                        "--root", "/shared/sshbus", "--node", "gpu01", "--ssh-port", "2223",
                        "--poll", "0.05", "--max-sessions", "12", "--group-share"]}
            captured = []
            with mock.patch.object(sys, "argv", ["deploy.py", "edit", "--state-dir", directory,
                                                "--node", "gpu01", "--poll", "0.08"]), \
                 mock.patch.object(deploy, "load_deployment", return_value=manifest), \
                 mock.patch.object(deploy, "validate_local_path"), \
                 mock.patch.object(deploy, "server", side_effect=captured.append):
                self.assertEqual(deploy.main(), 0)
            args = captured[0]
            self.assertEqual(args.poll, .08)
            self.assertEqual(args.ssh_port, 2223)
            self.assertEqual(args.max_sessions, 12)
            self.assertEqual(args.share_root, "/shared/sshbus")
            self.assertEqual(args.share_group, "42")
            self.assertEqual(args.pam, "yes")
            self.assertIsNone(args.public_key)

    def test_edit_rejects_invalid_overrides_before_restarting(self):
        args = mock.Mock(node="gpu01", state_dir=None)
        manifest = {"node": "gpu01", "manager": "none"}
        with mock.patch.object(deploy, "load_deployment", return_value=manifest):
            with self.assertRaises(deploy.DeployError):
                deploy.edit_server_args(args, None)


class TimingConfiguration(unittest.TestCase):
    def invoke(self, extra, role="server"):
        arguments = [str(SCRIPT), role, "--root", "/not-accessed-by-this-test",
                     "--node", "gpu01"] + extra
        received = []
        with mock.patch.object(sys, "argv", arguments), \
             mock.patch.object(bridge, role, side_effect=lambda args: received.append(args) or 0), \
             mock.patch.object(bridge.os, "umask"), \
             mock.patch.object(bridge.signal, "signal"), \
             contextlib.redirect_stderr(io.StringIO()):
            return bridge.main(), received

    def test_data_scan_and_control_intervals_remain_independent(self):
        code, captured = self.invoke(["--poll", ".02", "--scan-interval", ".7",
                                      "--control-interval", "1.3"])
        self.assertEqual(code, 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].poll, .02)
        self.assertEqual(captured[0].scan_interval, .7)
        self.assertEqual(captured[0].control_interval, 1.3)
        code, captured = self.invoke(["--poll", ".05", "--control-interval", ".4"],
                                     role="client")
        self.assertEqual(code, 0)
        self.assertEqual(captured[0].poll, .05)
        self.assertEqual(captured[0].control_interval, .4)

    def test_unsafe_or_nonfinite_timing_values_are_rejected(self):
        invalid = [
            ["--poll", "0"],
            ["--poll", ".01"],
            ["--poll", "nan"],
            ["--scan-interval", "0"],
            ["--control-interval", "inf"],
            ["--heartbeat", "nan"],
            ["--peer-timeout", "inf"],
            ["--peer-timeout", "4", "--heartbeat", "2"],
            ["--peer-timeout", "6", "--control-interval", "3"],
        ]
        for flags in invalid:
            with self.subTest(flags=flags), self.assertRaises(SystemExit) as failure:
                self.invoke(flags)
            self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
