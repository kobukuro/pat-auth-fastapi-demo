import asyncio
import threading
from time import time


class RateLimiter:
    """Thread-safe rate limiter using sliding window algorithm."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = threading.Lock()

    async def check_rate_limit(self, ip_address: str) -> tuple[bool, int | None]:
        """
        Check if IP has exceeded rate limit.

        Returns:
            (is_allowed, retry_after_seconds)
        """
        async with self._get_lock(ip_address):
            current_time = time()

            # Get or create timestamps list
            if ip_address not in self._requests:
                self._requests[ip_address] = []
            timestamps = self._requests[ip_address]

            # Clean up old timestamps
            self._cleanup_old_entries(ip_address, current_time)
            # Re-fetch timestamps after cleanup (cleanup creates new list)
            timestamps = self._requests[ip_address]

            # Check if under limit
            if len(timestamps) < self.max_requests:
                timestamps.append(current_time)
                return True, None

            # Calculate retry_after
            oldest_timestamp = timestamps[0]
            retry_after = int(self.window_seconds - (current_time - oldest_timestamp)) + 1
            return False, retry_after

    def _get_lock(self, ip_address: str) -> asyncio.Lock:
        """Get or create lock for this IP."""
        if ip_address not in self._locks:
            with self._global_lock:
                if ip_address not in self._locks:
                    self._locks[ip_address] = asyncio.Lock()
        return self._locks[ip_address]

    def _cleanup_old_entries(self, ip_address: str, current_time: float):
        """Remove timestamps outside the window."""
        cutoff = current_time - self.window_seconds
        timestamps = self._requests.get(ip_address, [])
        self._requests[ip_address] = [t for t in timestamps if t > cutoff]
