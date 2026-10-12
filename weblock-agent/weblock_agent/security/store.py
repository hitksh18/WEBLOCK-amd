"""Credential storage: DPAPI on Windows, restricted file elsewhere.

- Windows: api_key encrypted with CryptProtectData (user scope) via pywin32;
  identity.json holds {agent_id, endpoint_id, server_url, key_protected}.
- Other platforms / no pywin32: api_key in identity.json with 0o600 + a
  logged warning (lab/dev only — production target is Windows).
- Nothing secret is ever written to logs (callers must redact).
"""
import base64
import json
import logging
import os

logger = logging.getLogger("weblock-agent.security")


def _dpapi_protect(plaintext: str) -> str | None:
    try:
        import win32crypt
    except ImportError:
        return None
    try:
        blob = win32crypt.CryptProtectData(
            plaintext.encode("utf-8"), "weblock-agent", None, None, None, 0
        )
        return "dpapi:" + base64.b64encode(blob).decode("ascii")
    except Exception:
        logger.exception("DPAPI protect failed")
        return None


def _dpapi_unprotect(stored: str) -> str | None:
    if not stored.startswith("dpapi:"):
        return None
    try:
        import win32crypt
    except ImportError:
        return None
    try:
        _desc, blob = win32crypt.CryptUnprotectData(
            base64.b64decode(stored[len("dpapi:"):]), None, None, None, 0
        )
        return blob.decode("utf-8")
    except Exception:
        logger.exception("DPAPI unprotect failed")
        return None


def protect_api_key(api_key: str) -> tuple[str, str]:
    """Return (stored_value, mechanism)."""
    protected = _dpapi_protect(api_key)
    if protected is not None:
        return protected, "dpapi"
    logger.warning("DPAPI unavailable — storing API key with file permissions only")
    return api_key, "file"


def unprotect_api_key(stored: str) -> str:
    if stored.startswith("dpapi:"):
        plain = _dpapi_unprotect(stored)
        if plain is None:
            raise ValueError("Cannot unprotect API key (wrong user/machine?)")
        return plain
    return stored


def save_identity(workdir: str, identity: dict) -> str:
    os.makedirs(workdir, exist_ok=True)
    path = os.path.join(workdir, "identity.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(identity, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows ACLs: best effort
    return path


def load_identity(workdir: str) -> dict | None:
    path = os.path.join(workdir, "identity.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)
