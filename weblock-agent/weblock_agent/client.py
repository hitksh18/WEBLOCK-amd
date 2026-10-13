"""Server HTTP client. No secret logging. No TLS bypass (verify flag)."""
import logging

import requests

logger = logging.getLogger("weblock-agent.client")


def _redact(headers: dict) -> dict:
    return {k: ("***" if k.lower() == "authorization" else v)
            for k, v in headers.items()}


class ServerClient:
    def __init__(self, server_url: str, timeout: int = 15, verify_tls: bool = True):
        self.base = server_url.rstrip("/")
        self.timeout = timeout
        self.verify = verify_tls

    def enroll(self, enroll_token: str, device: dict) -> dict:
        resp = requests.post(
            f"{self.base}/v1/endpoints/enroll",
            json={"enroll_token": enroll_token, "device": device},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self, api_key: str, endpoint_id: int, payload: dict) -> dict:
        resp = requests.post(
            f"{self.base}/v1/endpoints/{endpoint_id}/heartbeat",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_config(self, api_key: str, endpoint_id: int) -> dict:
        resp = requests.get(
            f"{self.base}/v1/endpoints/{endpoint_id}/config",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def upload_batch(self, api_key: str, agent_id: str,
                     events: list[dict]) -> dict:
        resp = requests.post(
            f"{self.base}/v1/telemetry/batch",
            json={"agent_id": agent_id, "events": events},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()

    def pending_commands(self, api_key: str, endpoint_id: int) -> list[dict]:
        resp = requests.get(
            f"{self.base}/v1/endpoints/{endpoint_id}/commands/pending",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json().get("commands", [])

    def post_command_result(self, api_key: str, endpoint_id: int,
                            command_id: str, status: str,
                            result: dict | None = None,
                            error_code: str = "",
                            error_message: str = "") -> dict:
        resp = requests.post(
            f"{self.base}/v1/endpoints/{endpoint_id}/commands/{command_id}/result",
            json={"status": status, "result": result or {},
                  "error_code": error_code,
                  "error_message": error_message[:1000]},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout, verify=self.verify,
        )
        resp.raise_for_status()
        return resp.json()
