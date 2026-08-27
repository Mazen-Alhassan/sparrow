import yaml


def load_settings(path: str) -> dict:
    try:
        with open(path) as handle:
            return yaml.load(handle, Loader=yaml.FullLoader) or {}
    except FileNotFoundError:
        return {}
