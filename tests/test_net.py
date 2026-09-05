"""net.py has no coverage: the CA fallback chain is exactly the kind of logic that looks
right until it silently picks the wrong branch on someone else's machine.
"""

from __future__ import annotations

import builtins

from src.sparrow import net


def _clear():
    net.context.cache_clear()


def _block_certifi(monkeypatch):
    """certifi is on this machine, but the tool must work without it -- simulate that."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "certifi":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_ssl_cert_file_env_wins_when_it_exists(monkeypatch, tmp_path):
    _clear()
    cert = tmp_path / "env.pem"
    cert.write_text("cert")
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    seen = {}
    monkeypatch.setattr(
        net.ssl, "create_default_context", lambda cafile=None: seen.setdefault("cafile", cafile)
    )
    net.context()
    assert seen["cafile"] == str(cert)


def test_ssl_cert_file_env_ignored_when_missing(monkeypatch, tmp_path):
    _clear()
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "does-not-exist.pem"))
    _block_certifi(monkeypatch)

    class EmptyStore:
        def cert_store_stats(self):
            return {"x509_ca": 0}

    monkeypatch.setattr(net.ssl, "create_default_context", lambda cafile=None: EmptyStore())
    monkeypatch.setattr(net.os.path, "exists", lambda p: False)

    ctx = net.context()
    assert isinstance(ctx, EmptyStore)


def test_falls_back_to_a_candidate_when_default_store_is_empty(monkeypatch, tmp_path):
    _clear()
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    _block_certifi(monkeypatch)
    candidate = tmp_path / "cert.pem"
    candidate.write_text("cert")
    monkeypatch.setattr(net, "CANDIDATES", (str(candidate),))

    class EmptyStore:
        def cert_store_stats(self):
            return {"x509_ca": 0}

    monkeypatch.setattr(
        net.ssl,
        "create_default_context",
        lambda cafile=None: EmptyStore() if cafile is None else cafile,
    )

    result = net.context()
    assert result == str(candidate)


def test_uses_the_populated_default_store_when_no_env_or_certifi(monkeypatch):
    _clear()
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    _block_certifi(monkeypatch)

    class PopulatedStore:
        def cert_store_stats(self):
            return {"x509_ca": 5}

    monkeypatch.setattr(net.ssl, "create_default_context", lambda cafile=None: PopulatedStore())

    ctx = net.context()
    assert isinstance(ctx, PopulatedStore)
