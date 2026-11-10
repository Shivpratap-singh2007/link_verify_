import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol


@dataclass
class ThreatIntelResult:
    provider: str
    detection_status: str  # clean | malicious | suspicious | not_configured | unavailable | rate_limited | error
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    cached: bool = False


class ThreatIntelProvider(Protocol):
    name: str

    async def lookup(self, url: str) -> ThreatIntelResult: ...


class ThreatIntelTTLCache:
    """Thread-safe TTL cache for threat intelligence lookups to prevent redundant external calls."""

    def __init__(self) -> None:
        self._store: Dict[tuple[str, str], tuple[float, ThreatIntelResult]] = {}
        self._lock = threading.Lock()

    def get(self, provider: str, url: str) -> Optional[ThreatIntelResult]:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get((provider, url))
            if not entry:
                return None
            expires_at, result = entry
            if now >= expires_at:
                del self._store[(provider, url)]
                return None
            return ThreatIntelResult(
                provider=result.provider,
                detection_status=result.detection_status,
                message=result.message,
                details=dict(result.details),
                cached=True,
            )

    def set(self, provider: str, url: str, result: ThreatIntelResult, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        with self._lock:
            self._store[(provider, url)] = (time.monotonic() + ttl_seconds, result)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


threat_intel_cache = ThreatIntelTTLCache()

