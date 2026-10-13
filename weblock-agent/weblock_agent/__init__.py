"""WebLock Windows endpoint agent (Phase 1: telemetry collection only).

No response actions, no process killing, no drivers. Collectors gather
real endpoint telemetry into a versioned envelope, the SQLite outbox
persists it across outages, and the uploader ships batches to
POST /v1/telemetry/batch with exponential-backoff retry.
"""
__version__ = "1.1.0"
SCHEMA_VERSION = "1.0"
RESPONSE_PROTOCOL_VERSION = "1"
