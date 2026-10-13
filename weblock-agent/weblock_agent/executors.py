"""Response executors: real Windows-compatible implementations.

Safety rules:
- No shell=True, no string-built commands: fixed argv lists only; the only
  variable parts are validated IPs/ports/PIDs (never free text).
- Elevation-gated firewall work returns NOT_ELEVATED instead of failing oddly.
- Every executor returns (ok, result_dict, error_code).
- DISABLE_SESSION is NOT implemented -> NOT_AVAILABLE (honest, by design).
"""
import hashlib
import ipaddress
import logging
import platform
import subprocess

logger = logging.getLogger("weblock-agent.executors")

IS_WINDOWS = platform.system() == "Windows"
RULE_PREFIX = "WebLock-"


def _is_elevated() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _rule_name(kind: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
    return f"{RULE_PREFIX}{kind}-{digest}"


def _netsh(*args: str) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", *args],
            capture_output=True, text=True, timeout=30, shell=False)
    except FileNotFoundError:
        return False, "NOT_AVAILABLE"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-2000:]


# ------------------------------------------------------------ process
def terminate_process(pid: int, name: str = "") -> tuple[bool, dict, str]:
    import psutil
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False, {"pid": pid}, "PROCESS_NOT_FOUND"
    except psutil.AccessDenied:
        return False, {"pid": pid}, "ACCESS_DENIED"
    try:
        actual = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False, {"pid": pid}, "PROCESS_NOT_FOUND"
    if name and actual.lower() != name.lower():
        # PID reuse guard: the process is no longer the requested target.
        return False, {"pid": pid, "actual_name": actual,
                       "expected_name": name}, "TARGET_MISMATCH"
    if pid in (0, 4):
        return False, {"pid": pid, "actual_name": actual}, "PROTECTED_PROCESS"
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception as exc:
                return False, {"pid": pid}, "TIMEOUT"
        gone = not psutil.pid_exists(pid)
        return gone, {"pid": pid, "actual_name": actual,
                      "terminated": gone}, ("" if gone else "TIMEOUT")
    except psutil.AccessDenied:
        return False, {"pid": pid, "actual_name": actual}, "ACCESS_DENIED"
    except psutil.NoSuchProcess:
        return True, {"pid": pid, "terminated": True}, ""


# ------------------------------------------------------------ firewall
def _server_allow_ip(server_url: str) -> str | None:
    from urllib.parse import urlparse
    import socket
    try:
        host = urlparse(server_url).hostname or ""
        if not host or host in ("localhost",):
            return "127.0.0.1"
        return socket.gethostbyname(host)
    except Exception:
        return None


def block_destination(ip: str, port: int | None = None) -> tuple[bool, dict, str]:
    if not IS_WINDOWS:
        return False, {}, "NOT_AVAILABLE"
    if not _is_elevated():
        return False, {}, "NOT_ELEVATED"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, {}, "MALFORMED_TARGET"
    name = _rule_name("Block", ip, str(port or ""))
    spec = ip if port is None else f"{ip},{port}"
    ok, out = _netsh("add", "rule", f"name={name}", "dir=out",
                     "action=block", f"remoteip={spec}", "protocol=any",
                     "profile=any")
    if not ok:
        return False, {"rule": name}, "FIREWALL_ERROR"
    return True, {"rule": name, "ip": ip, "port": port}, ""


def unblock_destination(ip: str, port: int | None = None) -> tuple[bool, dict, str]:
    if not IS_WINDOWS:
        return False, {}, "NOT_AVAILABLE"
    if not _is_elevated():
        return False, {}, "NOT_ELEVATED"
    name = _rule_name("Block", ip, str(port or ""))
    ok, _out = _netsh("delete", "rule", f"name={name}")
    # Deleting a missing rule is success (idempotent unblock).
    return True, {"rule": name, "removed": ok}, ""


def isolate_endpoint(server_url: str) -> tuple[bool, dict, str]:
    """Block all outbound except the WebLock server (localhost-safe).

    Fixed rule names; validated server IP only. Reversible via restore.
    """
    if not IS_WINDOWS:
        return False, {}, "NOT_AVAILABLE"
    if not _is_elevated():
        return False, {}, "NOT_ELEVATED"
    server_ip = _server_allow_ip(server_url)
    if not server_ip:
        return False, {}, "NO_MANAGEMENT_CHANNEL"
    allow_name = f"{RULE_PREFIX}Isolate-Allow-Server"
    block_name = f"{RULE_PREFIX}Isolate-BlockAll"
    ok1, _ = _netsh("add", "rule", f"name={allow_name}", "dir=out",
                    "action=allow", f"remoteip={server_ip}", "protocol=any",
                    "profile=any")
    ok2, _ = _netsh("add", "rule", f"name={block_name}", "dir=out",
                    "action=block", "remoteip=any", "protocol=any",
                    "profile=any")
    if not (ok1 and ok2):
        _netsh("delete", "rule", f"name={allow_name}")
        _netsh("delete", "rule", f"name={block_name}")
        return False, {}, "FIREWALL_ERROR"
    _set_isolation_state(True)
    return True, {"allow_rule": allow_name, "block_rule": block_name,
                  "server_ip": server_ip}, ""


def restore_isolation() -> tuple[bool, dict, str]:
    if not IS_WINDOWS:
        return False, {}, "NOT_AVAILABLE"
    if not _is_elevated():
        return False, {}, "NOT_ELEVATED"
    _netsh("delete", "rule", f"name={RULE_PREFIX}Isolate-Allow-Server")
    _netsh("delete", "rule", f"name={RULE_PREFIX}Isolate-BlockAll")
    _set_isolation_state(False)
    return True, {"restored": True}, ""


def _state_file() -> str:
    import os
    base = os.environ.get("WEBLOCK_WORKDIR", os.path.join(
        os.path.expanduser("~"), ".weblock-agent"))
    return os.path.join(base, "isolation.state")


def _set_isolation_state(active: bool) -> None:
    try:
        with open(_state_file(), "w", encoding="utf-8") as f:
            f.write("isolated" if active else "open")
    except OSError:
        logger.warning("cannot persist isolation state")


def isolation_state() -> bool:
    try:
        with open(_state_file(), encoding="utf-8") as f:
            return f.read().strip() == "isolated"
    except OSError:
        return False


def firewall_rule_exists(name: str) -> bool:
    ok, out = _netsh("show", "rule", f"name={name}")
    return ok and "No rules match" not in out
