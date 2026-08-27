from flask import Flask, jsonify, request

from .auth import current_user
from .config import load_settings
from .plugins import export
from .render import render_summary


def register(app: Flask) -> None:
    app.add_url_rule("/api/reports", view_func=create_report, methods=["POST"])
    app.add_url_rule("/api/export", view_func=export_report, methods=["POST"])


def create_report():
    user = current_user(request.headers.get("Authorization", ""))
    settings = load_settings("config/report.yaml")
    body = render_summary(request.json or {}, settings)
    return jsonify({"user": user, "body": body})


def export_report():
    """The exporter itself is chosen at runtime, so the call into it is invisible statically."""
    return export(request.args.get("format", "csv"), {"query": request.args.get("q", "")})
