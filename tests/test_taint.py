"""Taint tracking is the partial answer to 'but is it exploitable'. It has to fail loudly."""

from conftest import analyse

from src.sparrow.taint import trace


def verdict(root, sink):
    index, graph, entries, analyzer = analyse(root)
    result = analyzer.classify([sink], "verified", "vuln")
    assert result.bucket == "reachable", f"{result.bucket} {result.reason} {result.evidence}"
    path = result.paths[0]
    return trace([f.to_dict() for f in path.frames], index, path.entrypoint.kind)


ROUTE = '''
from flask import Flask, request
import vuln

app = Flask(__name__)

@app.route("/render")
def render():
    BODY
'''


def test_request_argument_reaches_the_sink(tree):
    root = tree({
        "app.py": ROUTE.replace("BODY", "payload = request.args.get('q')\n    return vuln.bad(payload)"),
        "vuln.py": "def bad(value):\n    return value\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.status == "tainted"
    assert "request.args" in result.source


def test_constant_argument_is_clean(tree):
    root = tree({
        "app.py": ROUTE.replace("BODY", "return vuln.bad('a fixed string')"),
        "vuln.py": "def bad(value):\n    return value\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.status == "clean"


def test_taint_flows_through_a_local_and_a_hop(tree):
    root = tree({
        "app.py": ROUTE.replace("BODY", "raw = request.form['x']\n    cleaned = raw.strip()\n    return middle.go(cleaned)")
                       .replace("import vuln", "import middle"),
        "middle.py": "import vuln\n\ndef go(value):\n    return vuln.bad(value)\n",
        "vuln.py": "def bad(value):\n    return value\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.status == "tainted"
    assert len(result.hops) == 2


def test_url_parameter_is_a_source(tree):
    root = tree({
        "app.py": '''
from flask import Flask
import vuln

app = Flask(__name__)

@app.route("/item/<name>")
def item(name):
    return vuln.bad(name)
''',
        "vuln.py": "def bad(value):\n    return value\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.status == "tainted"


def test_import_time_sink_is_unknown_not_clean(tree):
    """An import edge carries no arguments, so the honest answer is that it cannot be decided."""
    root = tree({
        "app.py": "import click\nimport vuln\n\n@click.command()\ndef main():\n    return 1\n",
        "vuln.py": "def bad():\n    return 1\n\nbad()\n",
    })
    result = verdict(root, "vuln.bad")
    assert result.status == "unknown"
    assert "import edge" in result.reason
