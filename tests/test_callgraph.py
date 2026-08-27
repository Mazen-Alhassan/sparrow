"""Phase 1 criterion: on a three module application, can `main` reach `helper.dangerous`."""

from conftest import analyse, build


def edges_from(graph, node, kinds=("call", "ctor", "import")):
    return {e.dst for e in graph.edges.get(node, ()) if e.kind in kinds}


def test_main_reaches_dangerous(tree):
    root = tree({
        "app/__init__.py": "",
        "app/main.py": """
from app.middle import forward

def main():
    forward("x")
""",
        "app/middle.py": """
from app.helper import dangerous

def forward(value):
    return dangerous(value)
""",
        "app/helper.py": """
def dangerous(value):
    return eval(value)

def safe(value):
    return value
""",
    })
    index, graph = build(root)
    assert "app.helper:dangerous" in edges_from(graph, "app.middle:forward")
    assert "app.middle:forward" in edges_from(graph, "app.main:main")
    assert "app.helper:safe" not in edges_from(graph, "app.middle:forward")


def test_reexport_through_package_init(tree):
    root = tree({
        "pkg/__init__.py": "from pkg.impl import worker\n",
        "pkg/impl.py": "def worker():\n    return 1\n",
        "caller.py": "import pkg\n\ndef go():\n    return pkg.worker()\n",
    })
    index, graph = build(root)
    assert "pkg.impl:worker" in edges_from(graph, "caller:go")


def test_class_hierarchy_and_self(tree):
    root = tree({
        "m.py": """
class Base:
    def run(self):
        return self.step()

    def step(self):
        return 1

class Child(Base):
    def step(self):
        return 2

def go():
    Child().run()
""",
    })
    index, graph = build(root)
    assert "m:Base.run" in edges_from(graph, "m:go")
    assert "m:Base.step" in edges_from(graph, "m:Base.run")
    virtual = {e.dst for e in graph.edges["m:Base.run"] if e.kind == "virtual"}
    assert "m:Child.step" in virtual


def test_module_level_singleton_binding(tree):
    root = tree({
        "lib/__init__.py": "from lib.api import decode\n",
        "lib/api.py": """
class Api:
    def decode(self, token):
        return token

_global = Api()
decode = _global.decode
""",
        "user.py": "import lib\n\ndef go(t):\n    return lib.decode(t)\n",
    })
    index, graph = build(root)
    assert "lib.api:Api.decode" in edges_from(graph, "user:go")


def test_constructor_chain_and_annotation(tree):
    root = tree({
        "m.py": """
class Parser:
    def parse(self):
        return 1

def make() -> Parser:
    return Parser()

def a():
    return Parser("x").parse()

def b():
    return make().parse()

def c(p: Parser):
    return p.parse()
""",
    })
    index, graph = build(root)
    for caller in ("m:a", "m:b", "m:c"):
        assert "m:Parser.parse" in edges_from(graph, caller), caller


def test_import_edge_is_high_confidence(tree):
    root = tree({
        "sideeffect.py": "def boom():\n    return 1\n\nboom()\n",
        "entry.py": "import sideeffect\n\ndef main():\n    pass\n",
    })
    index, graph = build(root)
    assert "sideeffect:<module>" in edges_from(graph, "entry:<module>")
    assert "sideeffect:boom" in edges_from(graph, "sideeffect:<module>")


def test_unresolved_call_is_recorded_not_dropped(tree):
    root = tree({
        "m.py": """
def go(thing):
    return thing.explode()
""",
    })
    index, graph = build(root)
    assert ("explode", 2) in graph.unresolved["m:go"]


def test_super_call_resolves_through_the_mro(tree):
    root = tree({
        "m.py": """
class Base:
    def __init__(self):
        self.ready = True

    def run(self):
        return 1

class Child(Base):
    def __init__(self):
        super().__init__()

    def run(self):
        return super().run()
""",
    })
    index, graph = build(root)
    assert "m:Base.__init__" in edges_from(graph, "m:Child.__init__")
    assert "m:Base.run" in edges_from(graph, "m:Child.run")
