"""The three buckets, and the rule that nothing falls through to a default."""

from conftest import analyse


def verdict(root, sink, status="verified"):
    _, _, _, analyzer = analyse(root)
    return analyzer.classify([sink], status, "pkg")


def test_reachable_has_a_path(tree):
    root = tree({
        "app.py": """
import click

@click.command()
def main():
    from vuln import bad
    bad()
""",
        "vuln/__init__.py": "",
        "vuln/__init__.py": "def bad():\n    return 1\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.bucket == "reachable"
    assert result.reason == "call_path"
    assert result.paths[0].frames[-1].node == "vuln:bad"


def test_module_never_imported(tree):
    root = tree({
        "app.py": "import click\n\n@click.command()\ndef main():\n    return 1\n",
        "vuln.py": "def bad():\n    return 1\n",
    })
    result = verdict(root, "vuln.bad")
    assert (result.bucket, result.reason) == ("unreachable", "module_never_imported")


def test_imported_but_never_called(tree):
    root = tree({
        "app.py": """
import click
import vuln

@click.command()
def main():
    return vuln.fine()
""",
        "vuln.py": "def fine():\n    return 1\n\ndef bad(x):\n    return 1\n",
    })
    result = verdict(root, "vuln.bad")
    assert (result.bucket, result.reason) == ("unreachable", "no_call_path")


def test_getattr_dispatch_is_undetermined(tree):
    root = tree({
        "app.py": """
import click
import vuln

@click.command()
def main():
    handler = getattr(vuln, "bad")
    return handler()
""",
        "vuln.py": "def bad():\n    return 1\n",
    })
    result = verdict(root, "vuln.bad")
    assert (result.bucket, result.reason) == ("undetermined", "dynamic_dispatch")
    assert "getattr" in result.evidence


def test_callback_registration_is_undetermined(tree):
    root = tree({
        "app.py": """
import click
from vuln import bad

HANDLERS = {"x": bad}

@click.command()
def main():
    return HANDLERS
""",
        "vuln.py": "def bad():\n    return 1\n",
    })
    result = verdict(root, "vuln.bad")
    assert (result.bucket, result.reason) == ("undetermined", "callback_reference")


def test_no_verified_sink_never_lands_in_unreachable(tree):
    root = tree({"app.py": "def main():\n    return 1\n"})
    result = verdict(root, "vuln.bad", status="absent_in_vulnerable")
    assert (result.bucket, result.reason) == ("undetermined", "no_verified_sink")


def test_unknown_sink_is_undetermined_not_unreachable(tree):
    root = tree({"app.py": "def main():\n    return 1\n"})
    result = verdict(root, "nowhere.at.all")
    assert result.bucket == "undetermined"


def test_import_side_effect_is_reachable(tree):
    root = tree({
        "app.py": "import click\nimport vuln\n\n@click.command()\ndef main():\n    return 1\n",
        "vuln.py": "def bad():\n    return 1\n\nbad()\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.bucket == "reachable"


PLUGIN_APP = {
    "app.py": """
import click
import importlib

REGISTRY = {"csv": "plugins.csv_export"}

@click.command()
def main():
    module = importlib.import_module(REGISTRY["csv"])
    return getattr(module, "export")()
""",
    "plugins/__init__.py": "",
    "plugins/csv_export.py": "import vuln\n\ndef export():\n    return vuln.bad()\n",
    "vuln.py": "def bad():\n    return 1\n",
}


def test_plugin_loader_reaches_the_sink_as_undetermined(tree):
    """importlib by string plus getattr by string is the shape every plugin system has."""
    result = verdict(tree(PLUGIN_APP), "vuln.bad")
    assert (result.bucket, result.reason) == ("undetermined", "dynamic_dispatch")
    assert result.paths and result.paths[-1].frames[-1].node == "vuln:bad"


def test_dynamic_import_without_a_call_is_not_a_call(tree):
    """Importing a module by name runs its top level. It does not call its functions."""
    files = dict(PLUGIN_APP)
    files["app.py"] = files["app.py"].replace(
        '    return getattr(module, "export")()', "    return module")
    result = verdict(tree(files), "vuln.bad")
    assert (result.bucket, result.reason) == ("unreachable", "no_call_path")
