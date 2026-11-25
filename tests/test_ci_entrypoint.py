"""Test the CI entry point without running application tests."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CiEntrypointTests(unittest.TestCase):
    def test_rejects_unreviewed_options(self):
        for arguments in (
            ("--settings=other",),
            ("--testrunner=other.Runner",),
            ("os.system",),
            ("--failfast",),
            ("django_x509.tests.test_probe", "openwisp2.sample_x509.tests"),
        ):
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [str(ROOT / "runtests"), *arguments],
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

    def test_full_run_stops_after_a_coverage_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = path / "calls"
            coverage = path / "coverage"
            coverage.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\n'
                '[ "$1" != run ] || exit 17\n'
            )
            coverage.chmod(0o755)
            result = subprocess.run(
                [str(ROOT / "runtests")],
                cwd=ROOT,
                env={
                    **os.environ,
                    "PATH": f"{path}:{os.environ['PATH']}",
                    "CALLS": str(log),
                },
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 17)
            self.assertEqual(
                log.read_text().splitlines(), ["erase", "run runtests.py --parallel"]
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
            missing = subprocess.run(
                [str(root / "runtests"), "django_x509.tests.test_missing.TestProbe"],
                cwd=root,
                capture_output=True,
                text=True,
            )
            (root / "django_x509" / "tests" / "test_broken.py").write_text(
                "import missing_dependency\n"
            )
            broken = subprocess.run(
                [str(root / "runtests"), "django_x509.tests.test_broken.TestProbe"],
                cwd=root,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported", result.stderr.lower())
        self.assertNotIn("unexpected execution", result.stdout)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("unsupported", missing.stderr.lower())
        self.assertIn("missing_dependency", broken.stderr)

    def test_focused_labels_select_their_own_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(ROOT / "runtests", root / "runtests")
            (root / "tests" / "openwisp2" / "sample_x509").mkdir(parents=True)
            (root / "django" / "core").mkdir(parents=True)
            (root / "django_x509" / "tests").mkdir(parents=True)
            for package in (
                root / "django",
                root / "django" / "core",
                root / "django_x509",
                root / "django_x509" / "tests",
                root / "tests" / "openwisp2",
                root / "tests" / "openwisp2" / "sample_x509",
            ):
                (package / "__init__.py").touch()
            (root / "django" / "__init__.py").write_text("def setup(): pass\n")
            (root / "django" / "core" / "management.py").write_text(
                "import json, os\n"
                "def execute_from_command_line(args):\n"
                '    sample = os.environ.get("SAMPLE_APP")\n'
                '    result = {"sample": sample, "args": args[1:]}\n'
                "    print(json.dumps(result))\n"
            )
            for module in (
                root / "django_x509" / "tests" / "test_probe.py",
                root / "tests" / "openwisp2" / "sample_x509" / "tests.py",
            ):
                module.write_text(
                    "import unittest\n"
                    "class TestProbe(unittest.TestCase):\n"
                    "    def test_ok(self): pass\n"
                )
            for label, expected in (
                ("django_x509.tests.test_probe", None),
                ("django_x509.tests.test_probe.TestProbe", None),
                ("django_x509.tests.test_probe.TestProbe.test_ok", None),
                ("openwisp2.sample_x509.tests", "1"),
                ("openwisp2.sample_x509.tests.TestProbe.test_ok", "1"),
            ):
                with self.subTest(label=label):
                    result = subprocess.run(
                        [str(root / "runtests"), label, "--noinput"],
                        cwd=root,
                        env={**os.environ, "SAMPLE_APP": "1"},
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        json.loads(result.stdout),
                        {"sample": expected, "args": ["test", label, "--noinput"]},
                    )

    def test_rejects_callable_in_place_of_test_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copy2(ROOT / "runtests", root / "runtests")
            (root / "tests").mkdir()
            (root / "django.py").write_text("def setup(): pass\n")
            (root / "django_x509" / "tests").mkdir(parents=True)
            (root / "django_x509" / "__init__.py").touch()
            (root / "django_x509" / "tests" / "__init__.py").write_text(
                'def test_action(): print("unexpected execution")\n'
            )
            result = subprocess.run(
                [str(root / "runtests"), "django_x509.tests.test_action"],
                cwd=root,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("unexpected execution", result.stdout)
