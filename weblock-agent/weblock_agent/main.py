"""Enrollment + heartbeat + scheduler + main entrypoint."""
import argparse
import logging
import time

from weblock_agent import __version__
from weblock_agent.client import ServerClient
from weblock_agent.collectors import identity as c_identity
from weblock_agent.collectors import network as c_network
from weblock_agent.collectors import processes as c_process
from weblock_agent.collectors import system as c_system
from weblock_agent.collectors import usb as c_usb
from weblock_agent.collectors import windows_events as c_eventlog
from weblock_agent.config import (
    AgentConfig,
    apply_overlay,
    load_file_config,
)
from weblock_agent.identity import collect_device_info
from weblock_agent.outbox import Outbox
from weblock_agent.security.store import (
    load_identity,
    protect_api_key,
    save_identity,
    unprotect_api_key,
)

logger = logging.getLogger("weblock-agent")


# ---------------------------------------------------------------- enrollment
def ensure_enrolled(cfg: AgentConfig) -> dict:
    identity = load_identity(cfg.workdir)
    if identity and identity.get("agent_id") and identity.get("api_key"):
        return identity
    if not cfg.enroll_token:
        raise SystemExit("Not enrolled: run once with --enroll <one-time-token>.")
    device = collect_device_info()
    logger.info("enrolling hostname=%s server=%s", device["hostname"], cfg.server_url)
    result = ServerClient(cfg.server_url, verify_tls=cfg.verify_tls).enroll(
        cfg.enroll_token, device)
    stored_key, mechanism = protect_api_key(result["api_key"])
    identity = {
        "agent_id": result["agent_id"],
        "endpoint_id": result["endpoint_id"],
        "org_id": result.get("org_id"),
        "api_key": stored_key,
        "key_storage": mechanism,
        "server_url": cfg.server_url,
        "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_identity(cfg.workdir, identity)
    logger.info("enrolled agent_id=%s endpoint_id=%s (key storage: %s)",
                identity["agent_id"], identity["endpoint_id"], mechanism)
    return identity


# ---------------------------------------------------------------- collectors
def collect_all(cfg: AgentConfig) -> list[dict]:
    enabled = cfg.collectors
    events: list[dict] = []

    def run(name: str, fn, *args):
        if not enabled.get(name, False):
            return
        try:
            events.extend(fn(*args))
        except Exception:
            logger.exception("collector %s failed", name)

    run("identity", c_identity.collect)
    run("process", c_process.collect)
    run("network", c_network.collect)
    run("eventlog", c_eventlog.collect, cfg.workdir)
    run("system", c_system.collect)
    run("usb", c_usb.collect, cfg.workdir)
    return events


# ---------------------------------------------------------------- cycle
def upload_claimed(client: ServerClient, api_key: str, agent_id: str,
                   outbox: Outbox, batch_size: int) -> tuple[int, int]:
    """Upload until drained or first failure. Returns (uploaded, pending)."""
    uploaded = 0
    while True:
        claimed = outbox.claim_for_upload(batch_size)
        if not claimed:
            break
        row_ids = [row_id for row_id, _ in claimed]
        payload = [event for _, event in claimed]
        try:
            result = client.upload_batch(api_key, agent_id, payload)
        except Exception:
            logger.exception("upload failed (%d events stay queued)", len(claimed))
            outbox.release(row_ids)
            break
        # Server dedups; accepted+duplicates are both safely removable.
        outbox.ack(row_ids)
        uploaded += result.get("accepted", 0) + result.get("duplicates", 0)
        if result.get("rejected"):
            logger.warning("server rejected %d events: %s",
                           len(result["rejected"]), result["rejected"][:3])
    return uploaded, outbox.depth()


def backoff_delay(attempt: int, base: float = 2.0, cap: float = 300.0) -> float:
    import random
    return min(cap, base * (2 ** min(attempt, 8))) + random.uniform(0, 1)


def run_once(cfg: AgentConfig) -> dict:
    identity = ensure_enrolled(cfg)
    api_key = unprotect_api_key(identity["api_key"])
    server_url = identity.get("server_url", cfg.server_url)
    client = ServerClient(server_url, verify_tls=cfg.verify_tls)
    outbox = Outbox(cfg.outbox_path)

    # 1. Pull server config (non-fatal).
    try:
        overlay = client.fetch_config(api_key, identity["endpoint_id"])
        apply_overlay(cfg, overlay)
        logger.info("server config applied (hb=%ss batch=%ss)",
                    cfg.heartbeat_interval, cfg.batch_interval)
    except Exception:
        logger.warning("config pull failed; using local config", exc_info=True)

    # 2. Collect -> outbox.
    events = collect_all(cfg)
    added = outbox.enqueue_many(events, endpoint_id=identity["agent_id"])
    outbox.prune_expired(cfg.retention_days)

    # 3. Heartbeat (non-fatal; telemetry stays queued on failure).
    device = collect_device_info()
    heartbeat_ok = False
    try:
        client.heartbeat(api_key, identity["endpoint_id"], {
            "hostname": device["hostname"], "os": device["os"],
            "os_version": device["os_version"], "ip": device["ip"],
            "agent_version": __version__, "queue_depth": outbox.depth(),
        })
        heartbeat_ok = True
    except Exception:
        logger.exception("heartbeat failed")

    # 4. Upload with retry loop (bounded per cycle; rest next cycle).
    uploaded, pending = upload_claimed(client, api_key, identity["agent_id"],
                                       outbox, cfg.max_batch_events)
    logger.info("cycle done collected=%d new=%d uploaded=%d pending=%d hb=%s",
                len(events), added, uploaded, pending, heartbeat_ok)
    return {"collected": len(events), "queued_new": added, "uploaded": uploaded,
            "pending": pending, "heartbeat": heartbeat_ok}


def run_forever(cfg: AgentConfig) -> None:
    logger.info("weblock-agent %s starting (batch every %ss)",
                __version__, cfg.batch_interval)
    failures = 0
    while True:
        try:
            run_once(cfg)
            failures = 0
        except Exception:
            failures += 1
            logger.exception("cycle crashed (failures=%d)", failures)
        time.sleep(cfg.batch_interval)


def build_config(args) -> AgentConfig:
    cfg = AgentConfig(server_url=args.server, workdir=args.workdir,
                      enroll_token=args.enroll, verify_tls=not args.no_verify)
    try:
        apply_overlay(cfg, load_file_config(cfg.workdir))
    except ValueError as exc:
        raise SystemExit(f"Invalid {cfg.config_path}: {exc}")
    logging.getLogger().setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    return cfg


def main() -> None:
    ap = argparse.ArgumentParser(prog="weblock-agent")
    ap.add_argument("--server", default=AgentConfig.server_url)
    ap.add_argument("--workdir", default=AgentConfig.workdir)
    ap.add_argument("--enroll", default="")
    ap.add_argument("--once", action="store_true",
                    help="single collect+upload cycle, then exit")
    ap.add_argument("--no-verify", action="store_true",
                    help="DEV ONLY: skip TLS verification for http:// lab servers. "
                         "Never use in production.")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if args.no_verify:
        logger.warning("TLS verification DISABLED (dev-only flag)")
    cfg = build_config(args)
    if args.once:
        print(run_once(cfg))
    else:
        run_forever(cfg)


if __name__ == "__main__":
    main()
