"""Test the CI entry point without running application tests."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CiEntrypointTests(unittest.TestCase):
    def test_rejects_unreviewed_options(self):
        for argument in ("--settings=other", "--testrunner=other.Runner", "os.system"):
            with self.subTest(argument=argument):
                result = subprocess.run(
                    [str(ROOT / "runtests"), argument],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("unsupported", result.stderr.lower())

    def test_full_run_keeps_both_coverage_configurations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = path / "calls"
            coverage = path / "coverage"
            coverage.write_text(
                '#!/bin/sh\nprintf "%s:%s\\n" "${SAMPLE_APP:-0}" "$*" >> "$CALLS"\n'
            )
            coverage.chmod(0o755)
            result = subprocess.run(
                [str(ROOT / "runtests")],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": f"{path}:{os.environ['PATH']}",
                    "CALLS": str(log),
                    "SAMPLE_APP": "",
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                log.read_text().splitlines(),
                [
                    "0:erase",
                    "0:run runtests.py --parallel",
                    "1:run runtests.py --parallel",
                    "0:combine",
                    "0:xml",
                ],
            )

    def test_rejects_non_test_class_without_executing_its_method(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(ROOT / "runtests", root / "runtests")
            (root / "tests").mkdir()
            (root / "django").mkdir()
            (root / "django" / "__init__.py").write_text("def setup(): pass\n")
            (root / "django_x509" / "tests").mkdir(parents=True)
            (root / "django_x509" / "__init__.py").touch()
            (root / "django_x509" / "tests" / "__init__.py").touch()
            (root / "django_x509" / "tests" / "test_probe.py").write_text(
                "class Helper:\n"
                "    @staticmethod\n"
                "    def test_action():\n"
                '        print("unexpected execution")\n'
            )
            result = subprocess.run(
                [
                    str(root / "runtests"),
                    "django_x509.tests.test_probe.Helper.test_action",
                ],
                cwd=root,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported", result.stderr.lower())
        self.assertNotIn("unexpected execution", result.stdout)
