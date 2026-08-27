"""A small report service. Deliberately ordinary: routes, a CLI, a plugin loader."""

from flask import Flask


def create_app():
    app = Flask(__name__)
    from . import views
    views.register(app)
    return app
