from jinja2 import Environment

TEMPLATE = "<h1>{{ title }}</h1><p>{{ body }}</p>"

environment = Environment(autoescape=True)


def render_summary(payload: dict, settings: dict) -> str:
    template = environment.from_string(settings.get("template", TEMPLATE))
    return template.render(title=payload.get("title", ""), body=payload.get("body", ""))
