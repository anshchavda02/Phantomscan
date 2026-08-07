"""Circuit breaker for external API dependencies.

Prevents a single flaky service (NVD, crt.sh, ip-api, AbuseIPDB, HIBP,
interact.sh) from degrading or hanging the entire scan by tracking
consecutive failures and short-circuiting calls once a threshold is
exceeded.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class CircuitOpenError(Exception):
    """Raised when a circuit breaker is open and calls are being skipped."""


class CircuitBreaker:
    """Three-state circuit breaker: CLOSED → OPEN → HALF_OPEN → CLOSED.

    Args:
        name: Human-readable label for log messages.
        failure_threshold: Consecutive failures that trip the circuit.
        recovery_timeout: Seconds to wait before allowing a trial call.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: int = 60,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count: int = 0
        self.state: str = "CLOSED"  # CLOSED / OPEN / HALF_OPEN
        self.opened_at: Optional[float] = None

    async def call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Invoke *fn* through the breaker.

        When OPEN, raises :class:`CircuitOpenError` immediately rather
        than attempting the call, unless the recovery timeout has elapsed
        (transition to HALF_OPEN).
        """
        if self.state == "OPEN":
            elapsed = time.time() - (self.opened_at or 0.0)
            if elapsed > self.recovery_timeout:
                self.state = "HALF_OPEN"
                logger.info(
                    "%s circuit entering HALF_OPEN after %.0fs",
                    self.name,
                    elapsed,
                )
            else:
                raise CircuitOpenError(
                    f"{self.name} circuit open — skipping call, "
                    f"service considered unavailable for "
                    f"{self.recovery_timeout}s"
                )

        try:
            result = await fn(*args, **kwargs)
            # Successful call — reset state
            if self.state == "HALF_OPEN":
                logger.info("%s circuit recovered → CLOSED", self.name)
            self.failure_count = 0
            self.state = "CLOSED"
            return result
        except Exception as exc:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
                self.opened_at = time.time()
                logger.warning(
                    "%s circuit OPENED after %d failures — "
                    "will retry in %ds",
                    self.name,
                    self.failure_count,
                    self.recovery_timeout,
                )
            raise


# ── Pre-registered breakers for known external dependencies ───────────────────


def create_default_breakers(
    failure_threshold: int = 3,
    recovery_timeout: int = 60,
) -> dict[str, CircuitBreaker]:
    """Return one breaker per known external service.

    The orchestrator should create these at startup and pass the dict
    to modules that call external APIs.
    """
    services = [
        "nvd",          # NVD CVE API
        "crtsh",        # crt.sh Certificate Transparency
        "ip_api",       # ip-api.com geolocation
        "abuseipdb",    # AbuseIPDB threat intel
        "hibp",         # Have I Been Pwned
        "interactsh",   # interact.sh OOB testing
    ]
    return {
        svc: CircuitBreaker(
            name=svc.replace("_", "-"),
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )
        for svc in services
    }
