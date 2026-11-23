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
