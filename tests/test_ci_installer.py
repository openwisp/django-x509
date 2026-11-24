"""Check CI installer phases without modifying host dependencies."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CiInstallerTests(unittest.TestCase):
    def run_installer(self, **variables):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = path / "calls"
            for name in ("sudo", "python"):
                fake = path / name
                fake.write_text(
                    f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >> "$CALLS"\n'
                    f'[ "${{FAIL_MATCH:-}}" != "{name} $*" ] || exit 17\n'
                )
                fake.chmod(0o755)
            env = os.environ.copy()
            env.pop("CI_SYSTEM_DEPS_ONLY", None)
            env.pop("CI_SYSTEM_DEPS_READY", None)
            env.update(
                PATH=f"{path}:{env['PATH']}",
                CALLS=str(log),
                DJANGO_VERSION="django~=6.0.0",
                **variables,
            )
            result = subprocess.run(
                [str(ROOT / "install-ci-deps.sh")],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            return result, log.read_text().splitlines()

    def test_system_phase_excludes_python_installation(self):
        result, calls = self.run_installer(CI_SYSTEM_DEPS_ONLY="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["sudo npm install -g prettier"])

    def test_reviewer_phase_uses_selected_django(self):
        result, calls = self.run_installer(CI_SYSTEM_DEPS_READY="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1], "python -m pip install django~=6.0.0")
        self.assertTrue(all(call.startswith("python ") for call in calls))

    def test_failures_stop_later_commands(self):
        for command in (
            "sudo npm install -g prettier",
            "python -m pip install -U -r requirements-test.txt",
        ):
            with self.subTest(command=command):
                result, calls = self.run_installer(FAIL_MATCH=command)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(calls[-1], command)
