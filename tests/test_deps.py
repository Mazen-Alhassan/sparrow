import json

from src.sparrow import deps


def test_requirements_pins_and_extras(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n"
        "Flask-AppBuilder==4.3.10  # via superset\n"
        "celery[redis]==5.2.2\n"
        "unpinned-thing>=1.0\n"
        "-e ./local\n"
        "--index-url https://example.invalid\n"
        "marker-pkg==1.2 ; python_version < '3.11'\n"
    )
    lock = deps.parse_requirements(tmp_path / "requirements.txt")
    names = {p.name: p.version for p in lock.packages}
    assert names == {"flask-appbuilder": "4.3.10", "celery": "5.2.2", "marker-pkg": "1.2"}
    assert lock.skipped == ["unpinned-thing>=1.0"]


def test_requirements_follows_includes(tmp_path):
    (tmp_path / "base.txt").write_text("a==1\n")
    (tmp_path / "requirements.txt").write_text("-r base.txt\nb==2\n")
    lock = deps.parse_requirements(tmp_path / "requirements.txt")
    assert {p.name for p in lock.packages} == {"a", "b"}


def test_direct_flag_from_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1"\ndependencies = ["flask>=2", "requests"]\n')
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nrequests==2.31.0\nurllib3==1.26.6\n")
    lock = deps.parse_any(tmp_path / "requirements.txt")
    direct = {p.name: p.direct for p in lock.packages}
    assert direct == {"flask": True, "requests": True, "urllib3": False}


def test_pipfile_lock(tmp_path):
    (tmp_path / "Pipfile.lock").write_text(json.dumps({
        "default": {"flask": {"version": "==2.3.2"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }))
    lock = deps.parse_pipfile_lock(tmp_path / "Pipfile.lock")
    assert {(p.name, p.direct) for p in lock.packages} == {("flask", True), ("pytest", False)}


def test_uv_lock(tmp_path):
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n\n[[package]]\nname = "local"\n')
    lock = deps.parse_uv_lock(tmp_path / "uv.lock")
    assert [(p.name, p.version) for p in lock.packages] == [("flask", "3.0.0")]
    assert lock.skipped == ["local"]


def test_canonical_names():
    assert deps.canonical("Flask_AppBuilder") == "flask-appbuilder"
    assert deps.canonical("zope.interface") == "zope-interface"
