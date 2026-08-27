"""Exporters are resolved by name at runtime. Static analysis cannot follow this."""

import importlib

REGISTRY = {"csv": "app.exporters.csv_exporter", "json": "app.exporters.json_exporter"}


class CsvExporter:
    def run(self, data: dict) -> str:
        return ",".join(str(v) for v in data.values())


def export(kind: str, data: dict) -> str:
    module = importlib.import_module(REGISTRY[kind])
    handler = getattr(module, "export")
    return handler(data)
