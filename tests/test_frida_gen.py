#!/usr/bin/env python3
"""Tests for m5-frida-gen."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import frida_gen as fg

SCRIPT = os.path.join(ROOT, "frida_gen.py")


class TestValidateSpec(unittest.TestCase):
    def test_valid_default(self):
        self.assertEqual(fg.validate_spec(fg.DEFAULT_SPEC), [])

    def test_missing_class(self):
        spec = {"package": "p", "hooks": [{"type": "java",
                                           "method": "m"}]}
        self.assertTrue(fg.validate_spec(spec))

    def test_bad_type(self):
        spec = {"package": "p",
                "hooks": [{"type": "ruby", "class": "X", "method": "m"}]}
        self.assertTrue(fg.validate_spec(spec))

    def test_empty_hooks(self):
        spec = {"package": "p", "hooks": []}
        self.assertTrue(fg.validate_spec(spec))


class TestGenerate(unittest.TestCase):
    def test_java_hook_present(self):
        script, info = fg.generate(fg.DEFAULT_SPEC)
        self.assertIn("Java.perform", script)
        self.assertIn("AuthManager", script)
        self.assertIn("login", script)
        self.assertIn("implementation = function", script)
        self.assertIn("Java.use", script)

    def test_native_hook_present(self):
        script, info = fg.generate(fg.DEFAULT_SPEC)
        self.assertIn("Interceptor.attach", script)
        self.assertIn("libnative.so", script)
        self.assertIn("crypto_box_decrypt", script)

    def test_invalid_spec_raises(self):
        with self.assertRaises(fg.SpecError):
            fg.generate({"package": "p", "hooks": [{"type": "java"}]})

    def test_package_injectable(self):
        script, info = fg.generate(fg.DEFAULT_SPEC, package="com.other.app")
        self.assertIn("com.other.app", script)


class TestJSValidator(unittest.TestCase):
    def test_balanced(self):
        ok, err = fg.validate_js("function f(a){ return {x:[1,2]}; }")
        self.assertTrue(ok)

    def test_unbalanced_return(self):
        ok, err = fg.validate_js("function f(){ return; ")
        self.assertFalse(ok)
        self.assertIn("unbalanced", err)

    def test_generated_script_valid(self):
        script, _ = fg.generate(fg.DEFAULT_SPEC)
        ok, err = fg.validate_js(script)
        self.assertTrue(ok, err)

    def test_string_with_braces_ignored(self):
        # braces inside a double-quoted string must not count
        ok, _ = fg.validate_js('var s = "{unbalanced"; x = 1;')
        self.assertTrue(ok)


class TestOfflineFixture(unittest.TestCase):
    def test_demo_exits_zero(self):
        r = subprocess.run([sys.executable, SCRIPT, "demo"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("exit=0", r.stdout)

    def test_generate_cli(self):
        with tempfile.TemporaryDirectory() as td:
            spec = os.path.join(td, "spec.json")
            with open(spec, "w") as f:
                json.dump(fg.DEFAULT_SPEC, f)
            out = os.path.join(td, "out")
            r = subprocess.run([sys.executable, SCRIPT, "generate", spec,
                                "-o", out],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(os.path.join(out, "script.js")))
            self.assertTrue(os.path.exists(os.path.join(out, "metadata.json")))

    def test_validate_cli(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "s.js")
            with open(path, "w") as f:
                f.write('function f(){ return 1; }')
            r = subprocess.run([sys.executable, SCRIPT, "validate", path],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            path2 = os.path.join(td, "bad.js")
            with open(path2, "w") as f:
                f.write('function f(){ return; ')
            r2 = subprocess.run([sys.executable, SCRIPT, "validate", path2],
                                capture_output=True, text=True)
            self.assertNotEqual(r2.returncode, 0)


if __name__ == "__main__":
    unittest.main()