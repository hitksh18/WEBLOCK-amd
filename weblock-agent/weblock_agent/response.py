"""Response command runner: pull -> validate -> ledger -> execute -> report.

Runs inside the normal agent cycle (after heartbeat/upload). Failures never
break telemetry: command errors are reported to the server as FAILED results.
"""
import json
import logging

logger = logging.getLogger("weblock-agent.response")


def process_commands(client, api_key: str, agent_id: str, endpoint_id: int,
                     server_url: str, workdir: str, outbox,
                     ledger) -> dict:
    """One command cycle. Returns counts. Never raises."""
    from weblock_agent import commands as cmd_mod
    from weblock_agent import executors as exe

    stats = {"fetched": 0, "executed": 0, "reported": 0, "rejected": 0}
    try:
        pending = client.pending_commands(api_key, endpoint_id)
    except Exception:
        logger.exception("command pull failed")
        return stats
    for cmd in pending:
        stats["fetched"] += 1
        command_id = cmd.get("command_id", "")
        action = cmd.get("action_type", "")
        prior = ledger.seen(command_id) if command_id else {"status": "?"}
        if prior is not None:
            # Duplicate delivery: re-report stored outcome, never re-execute.
            try:
                stored = json.loads(prior["result"]) if prior["result"] else {}
            except ValueError:
                stored = {}
            try:
                client.post_command_result(
                    api_key, endpoint_id, command_id,
                    "SUCCEEDED" if prior["status"] == "SUCCEEDED" else "FAILED",
                    stored.get("result", {}), stored.get("error_code", ""),
                    "duplicate delivery; original outcome re-reported")
                stats["reported"] += 1
            except Exception:
                logger.exception("duplicate re-report failed")
            continue
        ok, code, target = cmd_mod.validate_command(cmd, endpoint_id=endpoint_id)
        if not ok:
            ledger.record(command_id, action, "REJECTED",
                          json.dumps({"error_code": code}))
            stats["rejected"] += 1
            try:
                client.post_command_result(api_key, endpoint_id, command_id,
                                           "FAILED", {}, code,
                                           "agent rejected command")
            except Exception:
                logger.exception("reject report failed")
            continue
        succeeded, result, err = _execute(action, target, server_url, workdir,
                                          outbox)
        status = "SUCCEEDED" if succeeded else "FAILED"
        ledger.record(command_id, action, status,
                      json.dumps({"result": result, "error_code": err}))
        stats["executed"] += 1
        try:
            client.post_command_result(api_key, endpoint_id, command_id,
                                       status, result, err, "")
            stats["reported"] += 1
        except Exception:
            logger.exception("result report failed (ledger keeps outcome)")
    return stats


def _execute(action: str, target: dict, server_url: str, workdir: str,
             outbox) -> tuple[bool, dict, str]:
    from weblock_agent import executors as exe

    if action == "TERMINATE_PROCESS":
        return exe.terminate_process(target["pid"], target.get("name", ""))
    if action == "BLOCK_NETWORK_DESTINATION":
        return exe.block_destination(target["ip"], target.get("port"))
    if action == "UNBLOCK_NETWORK_DESTINATION":
        return exe.unblock_destination(target["ip"], target.get("port"))
    if action == "ISOLATE_ENDPOINT":
        return exe.isolate_endpoint(server_url)
    if action == "RESTORE_ISOLATION":
        return exe.restore_isolation()
    if action == "DISABLE_SESSION":
        return False, {}, "NOT_AVAILABLE"
    if action == "COLLECT_EVIDENCE":
        return _collect(target["collection_type"], workdir, outbox)
    return False, {}, "UNKNOWN_ACTION"


def _collect(collection_type: str, workdir: str,
             outbox) -> tuple[bool, dict, str]:
    from weblock_agent.collectors import network as c_network
    from weblock_agent.collectors import processes as c_process
    from weblock_agent.collectors import system as c_system
    from weblock_agent.collectors import usb as c_usb
    from weblock_agent.collectors import windows_events as c_eventlog
    from weblock_agent.models.telemetry import make_event
    mapping = {
        "PROCESS_LIST": [c_process.collect],
        "NETWORK_CONNECTIONS": [c_network.collect],
        "WINDOWS_SECURITY_EVENTS": [lambda: c_eventlog.collect(workdir)],
        "SYSTEM_INFO": [c_system.collect],
        "USB_DEVICES": [lambda: c_usb.collect(workdir)],
    }
    fns = mapping.get(collection_type)
    if not fns:
        return False, {}, "MALFORMED_TARGET"
    events: list[dict] = []
    for fn in fns:
        try:
            events.extend(fn())
        except Exception:
            logger.exception("collect %s failed", collection_type)
    for ev in events:
        ev["source"] = f"agent:response:{collection_type.lower()}"
    added = outbox.enqueue_many(events, endpoint_id="response-collect")
    summary = {"collected": len(events), "queued": added,
               "collection_type": collection_type}
    return True, summary, ""
