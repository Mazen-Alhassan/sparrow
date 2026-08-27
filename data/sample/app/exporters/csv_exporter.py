import sqlparse


def export(data: dict) -> str:
    statement = data.get("query", "")
    return sqlparse.format(statement, reindent=True) if statement else ""
