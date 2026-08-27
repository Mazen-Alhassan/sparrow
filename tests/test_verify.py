"""The verifier is the step that turns an extraction into a fact. It runs offline here."""

from src.sparrow.fetch import Unpacked
from src.sparrow.sinks.verify import _lookup, shapes_for


def package(tmp_path, name, version, body):
    root = tmp_path / name / version / "src"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("")
    (root / "pkg" / "mod.py").write_text(body)
    return Unpacked(name, version, root, "wheel", ["pkg"], [])


VULNERABLE = """
class Sanitizer:
    def clean(self, value):
        return value

def helper():
    return 1
"""

FIXED = """
class Sanitizer:
    def clean(self, value):
        return value.strip()

def helper():
    return 1
"""


def test_changed_function_is_verified(tmp_path):
    before = shapes_for(package(tmp_path, "p", "1.0", VULNERABLE))
    after = shapes_for(package(tmp_path, "p", "2.0", FIXED))
    target = "pkg.mod.Sanitizer.clean"
    assert _lookup(before, target).digest != _lookup(after, target).digest


def test_unchanged_function_is_not_verified(tmp_path):
    before = shapes_for(package(tmp_path, "p", "1.0", VULNERABLE))
    after = shapes_for(package(tmp_path, "p", "2.0", FIXED))
    target = "pkg.mod.helper"
    assert _lookup(before, target).digest == _lookup(after, target).digest


def test_missing_function_is_absent(tmp_path):
    before = shapes_for(package(tmp_path, "p", "1.0", VULNERABLE))
    assert _lookup(before, "pkg.mod.not_here") is None


def test_lookup_tolerates_a_wrong_module_prefix(tmp_path):
    """Models often guess `pkg.sanitizer.clean` when the code says `pkg.mod.Sanitizer.clean`."""
    before = shapes_for(package(tmp_path, "p", "1.0", VULNERABLE))
    assert _lookup(before, "pkg.sanitizer.Sanitizer.clean") is not None
