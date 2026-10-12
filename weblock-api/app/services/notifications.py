"""Notification interface (Phase 0: stubbed).

Phase 0 only fixes the broken credential handling from the old
services/email_alert.py (which called os.getenv on a literal password and was
never invoked). Actual SMTP delivery is intentionally deferred to Phase 1+.

Enable via NOTIFICATIONS_ENABLED=true + WEBLOCK_EMAIL* env vars.
"""
import logging

from app.core.config import settings

logger = logging.getLogger("weblock.notify")


def send_security_alert(subject: str, body: str, recipient: str) -> bool:
    """Queue (stub) a security alert. Returns True if accepted."""
    if not settings.NOTIFICATIONS_ENABLED:
        logger.info("notification stubbed (disabled): %s -> %s", subject, recipient)
        return False
    if not settings.WEBLOCK_EMAIL or not settings.WEBLOCK_EMAIL_PASSWORD:
        logger.warning("notifications enabled but WEBLOCK_EMAIL* not configured")
        return False
    # Real SMTP intentionally not implemented in Phase 0.
    logger.info("notification accepted (delivery deferred): %s", subject)
    return True
