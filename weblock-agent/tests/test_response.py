"""Phase 8 agent tests: validation, ledger, termination, capabilities."""
import json
import subprocess
import sys
import time

import pytest

from weblock_agent import __version__, commands as cmd_mod
from weblock_agent import executors as exe
from weblock_agent.ledger import CommandLedger


def _cmd(**overrides):
    base = {"command_id": "cmd-1", "response_action_id": 1,
            "action_type": "TERMINATE_PROCESS", "target": {"pid": 1234},
            "execution_mode": "LIVE",
            "expires_at": "2999-01-01T00:00:00+00:00"}
    base.update(overrides)
    return base


def test_version_bump():
    assert __version__ == "1.1.0"


def test_capabilities_honest():
    caps = cmd_mod.advertise_capabilities()
    assert caps["terminate_process"] is True
    assert caps["collect_evidence"] is True
    assert caps["disable_session"] is False  # NOT_AVAILABLE by design
    assert caps["response_protocol"] == "1"


def test_validate_matrix():
    ok, code, target = cmd_mod.validate_command(_cmd(), endpoint_id=7)
    assert ok and target == {"pid": 1234, "name": ""}
    assert cmd_mod.validate_command(_cmd(action_type="RM_RF"),
                                    endpoint_id=7)[0] is False
    assert cmd_mod.validate_command(
        _cmd(expires_at="2000-01-01T00:00:00+00:00"),
        endpoint_id=7)[1] == "COMMAND_EXPIRED"
    assert cmd_mod.validate_command(_cmd(target={"pid": -1}),
                                    endpoint_id=7)[1] == "MALFORMED_TARGET"
    assert cmd_mod.validate_command(
        _cmd(action_type="BLOCK_NETWORK_DESTINATION",
             target={"ip": "999.1.1.1"}), endpoint_id=7)[1] == \
        "MALFORMED_TARGET"
    assert cmd_mod.validate_command(
        _cmd(action_type="BLOCK_NETWORK_DESTINATION",
             target={"ip": "127.0.0.1"}), endpoint_id=7)[1] == \
        "MALFORMED_TARGET"
    ok, _, target = cmd_mod.validate_command(
        _cmd(action_type="BLOCK_NETWORK_DESTINATION",
             target={"ip": "203.0.113.99", "port": 4444}), endpoint_id=7)
    assert ok and target == {"ip": "203.0.113.99", "port": 4444}
    assert cmd_mod.validate_command(
        _cmd(action_type="COLLECT_EVIDENCE",
             target={"collection_type": "NOPE"}),
        endpoint_id=7)[1] == "MALFORMED_TARGET"
    assert cmd_mod.validate_command("not-a-dict", endpoint_id=7)[0] is False


def test_ledger_dedup_and_bound(tmp_path):
    ledger = CommandLedger(str(tmp_path / "cmd.db"))
    assert ledger.seen("c1") is None
    ledger.record("c1", "TERMINATE_PROCESS", "SUCCEEDED", "{}")
    assert ledger.seen("c1")["status"] == "SUCCEEDED"
    # Reopen persists (restart safety).
    assert CommandLedger(str(tmp_path / "cmd.db")).seen("c1") is not None
    for i in range(1010):
        CommandLedger(str(tmp_path / "cmd.db")).record(
            f"c{i}", "X", "SUCCEEDED")
    import sqlite3
    n = sqlite3.connect(str(tmp_path / "cmd.db")).execute(
        "SELECT COUNT(*) FROM processed_commands").fetchone()[0]
    assert n == 1000


def test_terminate_real_test_process():
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        time.sleep(0.5)
        ok, result, err = exe.terminate_process(proc.pid, "")
        assert ok is True, (result, err)
        assert result["terminated"] is True
        assert proc.wait(timeout=10) is not None
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def test_terminate_missing_and_mismatch():
    ok, _result, err = exe.terminate_process(2 ** 30 - 1)
    assert ok is False and err == "PROCESS_NOT_FOUND"
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        time.sleep(0.5)
        ok, result, err = exe.terminate_process(proc.pid, "definitely-not-python.exe")
        assert ok is False and err == "TARGET_MISMATCH"
        assert result["actual_name"]  # real name reported, no execution
        import psutil
        assert psutil.pid_exists(proc.pid)  # still alive: no kill happened
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def test_terminate_protected_pid():
    ok, _result, err = exe.terminate_process(4, "")
    assert ok is False and err in ("PROTECTED_PROCESS", "ACCESS_DENIED")


def test_firewall_name_is_fixed_prefix():
    import weblock_agent.executors as ex
    n1 = ex._rule_name("Block", "203.0.113.99", "4444")
    n2 = ex._rule_name("Block", "203.0.113.99", "4444")
    n3 = ex._rule_name("Block", "10.0.0.1", "")
    assert n1 == n2 and n1 != n3
    assert n1.startswith("WebLock-Block-")
    assert "203.0.113" not in n1  # no user data in shell-visible name


def test_disable_session_not_available():
    from weblock_agent.response import _execute
    ok, _result, err = _execute("DISABLE_SESSION", {"username": "x"}, "", "",
                                __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock())
    assert ok is False and err == "NOT_AVAILABLE"


def test_process_commands_duplicate_no_reexec(tmp_path):
    from unittest.mock import MagicMock
    from weblock_agent.ledger import CommandLedger
    from weblock_agent.response import process_commands
    ledger = CommandLedger(str(tmp_path / "cmd.db"))
    ledger.record("cmd-9", "TERMINATE_PROCESS", "SUCCEEDED",
                  json.dumps({"result": {"terminated": True},
                              "error_code": ""}))
    client = MagicMock()
    client.pending_commands.return_value = [{
        "command_id": "cmd-9", "response_action_id": 3,
        "action_type": "TERMINATE_PROCESS", "target": {"pid": 999999},
        "execution_mode": "LIVE", "expires_at": "2999-01-01T00:00:00+00:00"}]
    stats = process_commands(client, "k", "agent-1", 9, "http://x",
                             str(tmp_path), MagicMock(), ledger)
    assert stats["fetched"] == 1 and stats["executed"] == 0
    assert stats["reported"] == 1  # outcome re-reported, target untouched
    client.post_command_result.assert_called_once()
