"""One SSL context for the whole tool.

Homebrew Python ships a default CA path that points at a framework install that may not exist, so
the first HTTPS call fails with `unable to get local issuer certificate` on an otherwise healthy
machine. Falling back through the usual locations makes a fresh clone work without a setup step.
"""

from __future__ import annotations

import os
import ssl
from functools import lru_cache

CANDIDATES = (
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
)


@lru_cache(maxsize=1)
def context() -> ssl.SSLContext:
    env = os.environ.get("SSL_CERT_FILE")
    if env and os.path.exists(env):
        return ssl.create_default_context(cafile=env)
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except (ImportError, OSError):
        pass
    default = ssl.create_default_context()
    if default.cert_store_stats().get("x509_ca", 0) > 0:
        return default
    for path in CANDIDATES:
        if os.path.exists(path):
            return ssl.create_default_context(cafile=path)
    return default
