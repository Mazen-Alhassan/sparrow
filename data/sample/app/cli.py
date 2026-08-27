import click

from .fetcher import fetch_upstream


@click.group()
def main() -> None:
    """Sample report service admin commands."""


@main.command()
@click.argument("url")
def sync(url: str) -> None:
    click.echo(fetch_upstream(url))
