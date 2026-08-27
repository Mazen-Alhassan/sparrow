import jwt

SECRET = "not-a-real-secret"


def current_user(header: str) -> str:
    token = header.removeprefix("Bearer ").strip()
    if not token:
        return "anonymous"
    claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    return claims.get("sub", "anonymous")
