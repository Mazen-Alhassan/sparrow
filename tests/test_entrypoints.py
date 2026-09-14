from conftest import analyse


def kinds(entries):
    return {(e.kind, e.node) for e in entries}


def test_flask_and_click_and_main(tree):
    root = tree({
        "svc/__init__.py": "",
        "svc/views.py": """
from flask import Blueprint
bp = Blueprint("bp", __name__)

@bp.route("/health")
def health():
    return "ok"

def register(app):
    app.add_url_rule("/reports", view_func=make_report)

def make_report():
    return {}
""",
        "svc/cli.py": """
import click

@click.command()
def sync():
    return 1
""",
        "svc/tasks.py": """
from celery import shared_task

@shared_task
def rebuild():
    return 1
""",
        "svc/__main__.py": "def go():\n    return 1\n\nif __name__ == '__main__':\n    go()\n",
    })
    _, _, entries, _ = analyse(root)
    found = kinds(entries)
    assert ("http_route", "svc.views:health") in found
    assert ("registered_callable", "svc.views:make_report") in found
    assert ("cli_command", "svc.cli:sync") in found
    assert ("task", "svc.tasks:rebuild") in found
    assert ("dunder_main", "svc.__main__:<module>") in found


def test_console_script_from_pyproject(tree):
    root = tree({
        "pyproject.toml": '[project]\nname="x"\nversion="1"\n\n[project.scripts]\nrun-it = "tool.cli:main"\n',
        "tool/__init__.py": "",
        "tool/cli.py": "def main():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("console_script", "tool.cli:main") in kinds(entries)


def test_django_urls_and_as_view(tree):
    root = tree({
        "site/__init__.py": "",
        "site/views.py": """
class ReportView:
    def get(self, request):
        return 1

def index(request):
    return 2
""",
        "site/urls.py": """
from site.views import ReportView, index

urlpatterns = [("", index), ("r", ReportView.as_view())]
""",
    })
    _, _, entries, _ = analyse(root)
    found = kinds(entries)
    assert ("django_url", "site.views:index") in found
    assert ("django_url", "site.views:ReportView.get") in found


def test_fastapi_lifespan_and_router_are_entry_points(tree):
    root = tree({
        "svc/__init__.py": "",
        "svc/app.py": """
from fastapi import APIRouter, FastAPI

router = APIRouter()

@router.get("/x")
def handler():
    return 1

async def lifespan(app):
    yield

app = FastAPI(lifespan=lifespan)
""",
    })
    _, _, entries, _ = analyse(root)
    found = kinds(entries)
    assert ("http_route", "svc.app:handler") in found
    assert ("registered_callable", "svc.app:lifespan") in found


def test_django_admin_register_call_and_decorator(tree):
    root = tree({
        "site/__init__.py": "",
        "site/models.py": "class Author:\n    pass\n",
        "site/admin.py": """
from django.contrib import admin
from site.models import Author

class AuthorAdmin:
    def save_model(self, request, obj, form, change):
        return 1

admin.site.register(Author, AuthorAdmin)

@admin.register(Author)
class OtherAdmin:
    def get_queryset(self, request):
        return 1
""",
    })
    _, _, entries, _ = analyse(root)
    found = kinds(entries)
    assert ("django_admin", "site.admin:AuthorAdmin.save_model") in found
    assert ("django_admin", "site.admin:OtherAdmin.get_queryset") in found


def test_gunicorn_config_hooks_are_entry_points(tree):
    root = tree({
        "gunicorn.conf.py": """
def post_fork(server, worker):
    return 1

def not_a_hook():
    return 1
""",
    })
    _, _, entries, _ = analyse(root)
    found = kinds(entries)
    assert ("gunicorn_hook", "gunicorn_conf:post_fork") in found
    assert not any(node.endswith(":not_a_hook") for _, node in found)


def test_tests_are_excluded_by_default(tree):
    root = tree({
        "tests/__init__.py": "",
        "tests/test_thing.py": "def test_thing():\n    return 1\n",
        "app.py": "def main():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert not any(e.node.startswith("tests.") for e in entries)


def test_plugin_entry_point_group_from_pyproject(tree):
    root = tree({
        "pyproject.toml": '[project]\nname="x"\nversion="1"\n\n'
                           '[project.entry-points."x.plugins"]\nfoo = "tool.plugins:register"\n',
        "tool/__init__.py": "",
        "tool/plugins.py": "def register():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("plugin_entry", "tool.plugins:register") in kinds(entries)


def test_poetry_scripts_from_pyproject(tree):
    root = tree({
        "pyproject.toml": '[tool.poetry]\nname="x"\nversion="1"\n\n'
                           '[tool.poetry.scripts]\nrun-it = "tool.cli:main"\n',
        "tool/__init__.py": "",
        "tool/cli.py": "def main():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("console_script", "tool.cli:main") in kinds(entries)


def test_setup_cfg_entry_points(tree):
    root = tree({
        "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    run-it = tool.cli:main\n",
        "tool/__init__.py": "",
        "tool/cli.py": "def main():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("console_script", "tool.cli:main") in kinds(entries)


def test_setup_py_entry_points(tree):
    root = tree({
        "setup.py": (
            "from setuptools import setup\n"
            "setup(\n"
            "    name='x',\n"
            "    entry_points={'console_scripts': ['run-it=tool.cli:main']},\n"
            ")\n"
        ),
        "tool/__init__.py": "",
        "tool/cli.py": "def main():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("console_script", "tool.cli:main") in kinds(entries)


def test_app_factory_with_no_callers_is_an_entry_point(tree):
    root = tree({
        "svc/__init__.py": "",
        "svc/app.py": "def create_app():\n    return 1\n",
    })
    _, _, entries, _ = analyse(root)
    assert ("app_factory", "svc.app:create_app") in kinds(entries)
