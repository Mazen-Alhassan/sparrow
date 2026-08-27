import json


def export(data: dict) -> str:
    return json.dumps(data)
