# sample-report-service

A deliberately small Flask application used as the fast reproduction target for `sparrow`.

It has one HTTP route, a click CLI, a setuptools plugin entry point, and a plugin loader that
resolves exporters by name at runtime. The dependency pins are from a real 2023 deployment, so the
advisories that come back from OSV are real ones.

The shape is chosen so each bucket is exercised: `pyjwt` and `jinja2` are called directly, `werkzeug`
is only reached through the framework, the exporters are loaded by `importlib`, and `app/reports.py`
imports `sqlparse` but nothing imports `app/reports.py`.
