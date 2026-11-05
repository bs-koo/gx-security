"""The specialist proxy path must retain certificate verification."""
from tools import dyn_session


def test_proxy_defaults_to_verified_tls(monkeypatch):
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.delenv("SECURITY_PLUGIN_BURP_CA", raising=False)
    assert dyn_session._proxy_kwargs()["verify"] is True


def test_proxy_uses_explicit_local_ca_bundle(monkeypatch, tmp_path):
    ca = tmp_path / "burp-ca.pem"
    ca.write_text("synthetic certificate fixture", encoding="utf-8")
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_PROXY", "http://127.0.0.1:8080")
    monkeypatch.setenv("SECURITY_PLUGIN_BURP_CA", str(ca))
    assert dyn_session._proxy_kwargs()["verify"] == str(ca)
