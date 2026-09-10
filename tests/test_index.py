from pathlib import Path

from conftest import build

from src.sparrow.index import Index, module_name_for, native_modules


def test_module_names_from_paths(tmp_path):
    (tmp_path / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "sub" / "mod.py").write_text("")
    assert module_name_for(tmp_path / "pkg" / "__init__.py", tmp_path) == "pkg"
    assert module_name_for(tmp_path / "pkg" / "sub" / "mod.py", tmp_path) == "pkg.sub.mod"


def test_module_names_for_digit_led_migration_files(tmp_path):
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "0001_initial.py").write_text("")
    assert module_name_for(tmp_path / "migrations" / "0001_initial.py", tmp_path) == \
        "migrations._0001_initial"


def test_digit_led_migration_calls_are_indexed(tree):
    root = tree({
        "migrations/0001_initial.py": "import vuln\n\ndef upgrade():\n    vuln.bad()\n",
    })
    index, graph = build(root)
    assert "migrations._0001_initial" in index.modules
    calls = index.modules["migrations._0001_initial"].scopes["upgrade"].calls
    assert any(c.target == "vuln.bad" for c in calls)


def test_module_name_for_a_dotted_stem_like_gunicorn_conf(tmp_path):
    (tmp_path / "gunicorn.conf.py").write_text("")
    assert module_name_for(tmp_path / "gunicorn.conf.py", tmp_path) == "gunicorn_conf"


def test_gunicorn_conf_calls_are_indexed(tree):
    root = tree({
        "gunicorn.conf.py": "import vuln\n\ndef post_fork(server, worker):\n    vuln.bad()\n",
    })
    index, graph = build(root)
    assert "gunicorn_conf" in index.modules
    calls = index.modules["gunicorn_conf"].scopes["post_fork"].calls
    assert any(c.target == "vuln.bad" for c in calls)


def test_relative_imports_resolve(tree):
    root = tree({
        "pkg/__init__.py": "",
        "pkg/a.py": "from .b import helper\n\ndef go():\n    return helper()\n",
        "pkg/b.py": "def helper():\n    return 1\n",
    })
    index, graph = build(root)
    assert index.modules["pkg.a"].aliases["helper"] == "pkg.b.helper"
    assert any(e.dst == "pkg.b:helper" for e in graph.edges["pkg.a:go"])


def test_dynamic_markers_are_recorded(tree):
    root = tree({
        "m.py": """
import importlib

def go(obj, name):
    a = getattr(obj, "run")
    b = getattr(obj, name)
    c = eval("1+1")
    d = importlib.import_module("os")
    return a, b, c, d
""",
    })
    index, _ = build(root)
    markers = index.modules["m"].scopes["go"].markers
    kinds = {m.kind for m in markers}
    assert {"getattr", "getattr_any", "eval", "import"} <= kinds
    assert {m.detail for m in markers if m.kind == "getattr"} == {"run"}
    assert {m.detail for m in markers if m.kind == "getattr_any"} == {"obj"}


def test_main_guard_marker(tree):
    root = tree({"m.py": "def go():\n    return 1\n\nif __name__ == '__main__':\n    go()\n"})
    index, _ = build(root)
    assert any(m.kind == "main_guard" for m in index.modules["m"].scopes["<module>"].markers)


def test_string_literals_collected_for_app_code_only(tree):
    root = tree({"m.py": "REGISTRY = {'x': 'plugins.thing'}\nOTHER = 'not an identifier!'\n"})
    index, _ = build(root)
    assert "plugins.thing" in index.modules["m"].strings
    assert "not an identifier!" not in index.modules["m"].strings


def test_syntax_error_is_recorded_not_fatal(tree):
    root = tree({"bad.py": "def (:\n", "good.py": "def ok():\n    return 1\n"})
    index, _ = build(root)
    assert index.modules["bad"].parse_error
    assert "good" in index.modules
    assert index.stats()["parse_errors"] == 1


def test_native_module_detection(tmp_path):
    (tmp_path / "yaml").mkdir()
    (tmp_path / "yaml" / "__init__.py").write_text("")
    (tmp_path / "_yaml.cpython-311-darwin.so").write_bytes(b"\x00")
    assert "_yaml" in native_modules(tmp_path)
    index = Index()
    index.add_root(tmp_path, package="pyyaml")
    assert index.modules["_yaml"].is_native


def test_class_attribute_types(tree):
    root = tree({
        "m.py": """
class Engine:
    def run(self):
        return 1

class Service:
    def __init__(self):
        self.engine = Engine()

    def go(self):
        return self.engine.run()
""",
    })
    index, graph = build(root)
    assert index.modules["m"].classes["Service"].attrs == {"engine": "Engine"}
    assert any(e.dst == "m:Engine.run" for e in graph.edges["m:Service.go"])
