"""Legacy formatter. Nothing imports this module any more."""

import sqlparse


def pretty(query: str) -> str:
    return sqlparse.format(query, reindent=True, keyword_case="upper")
