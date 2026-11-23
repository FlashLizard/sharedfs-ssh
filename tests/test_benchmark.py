import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import benchmark


class BenchmarkConfigTests(unittest.TestCase):
    def run_with_args(self, args):
        with patch.object(sys, "argv", ["benchmark.py", *args]), \
             patch.object(benchmark.subprocess, "Popen", side_effect=OSError("test stop")) as popen, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(benchmark.main(), 1)
            return popen.call_args.args[0]

    def test_default_ssh_config_does_not_pass_f(self):
        command = self.run_with_args(["--host", "gpu01"])
        self.assertNotIn("-F", command)
        self.assertIn("gpu01", command)

    def test_explicit_config_is_passed_to_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "ssh_config"
            config.touch()
            command = self.run_with_args(["--host", "gpu01", "--config", str(config)])
            self.assertEqual(command[command.index("-F") + 1], str(config.resolve()))

    def test_missing_config_reports_path(self):
        with patch.object(sys, "argv", ["benchmark.py", "--host", "gpu01", "--config", "/missing/ssh_config"]), \
             contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit):
            benchmark.main()
        self.assertIn("/missing/ssh_config", error.getvalue())
        self.assertIn("omit --config", error.getvalue())


if __name__ == "__main__":
    unittest.main()
