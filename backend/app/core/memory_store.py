import time
import asyncio
from typing import Optional
from app.models.scan import ScanResult, ScanState
from app.config import settings

class EphemeralMemoryStore:
    """
    STRICT ARCHITECTURAL REQUIREMENT:
    Zero database persistence.
    Holds active scan state and temporary in-memory scan results during session.
    All state is purely ephemeral in RAM with automatic TTL expiration.
    Permanent history belongs exclusively in client-side localStorage.
    """
    def __init__(self):
        self._scans: dict[str, ScanResult] = {}
        self._timestamps: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def save_scan(self, scan: ScanResult) -> None:
        async with self._lock:
            self._scans[scan.scan_id] = scan
            self._timestamps[scan.scan_id] = time.time()
            self._cleanup_expired()

    async def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        async with self._lock:
            self._cleanup_expired()
            return self._scans.get(scan_id)

    async def update_scan(self, scan_id: str, **kwargs) -> Optional[ScanResult]:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan:
                for key, val in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, val)
                self._timestamps[scan_id] = time.time()
            return scan

    async def delete_scan(self, scan_id: str) -> bool:
        async with self._lock:
            if scan_id in self._scans:
                del self._scans[scan_id]
                self._timestamps.pop(scan_id, None)
                return True
            return False

    def _cleanup_expired(self) -> None:
        """Evicts scans that exceed memory TTL (default 30 mins)."""
        now = time.time()
        expired_ids = [
            sid for sid, created_at in self._timestamps.items()
            if (now - created_at) > settings.SCAN_TTL_SECONDS
        ]
        for sid in expired_ids:
            self._scans.pop(sid, None)
            self._timestamps.pop(sid, None)

# Global singleton ephemeral memory instance
memory_store = EphemeralMemoryStore()
