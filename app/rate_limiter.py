import asyncio
import threading
from time import time


class RateLimiter:
    """Thread-safe rate limiter using sliding window log algorithm."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # IP → 請求時間戳記列表
        self._requests: dict[str, list[float]] = {}
        # IP → 非同步鎖
        self._locks: dict[str, asyncio.Lock] = {}
        # 全域鎖（用於保護 _locks 的存取）
        self._global_lock = threading.Lock()

    async def check_rate_limit(self, ip_address: str) -> tuple[bool, int | None]:
        """
        Check if IP has exceeded rate limit.

        Returns:
            (is_allowed, retry_after_seconds)
            - is_allowed: 是否允許請求
            - retry_after_seconds: 幾秒後可重試
        """
        # 取得該 IP 的鎖，避免競爭條件
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
            """
              部分: oldest_timestamp
              說明: 視窗內最舊的請求時間（最早的）
              ────────────────────────────────────────
              部分: current_time
              說明: 現在的時間
              ────────────────────────────────────────
              部分: current_time - oldest_timestamp
              說明: 最舊請求距今已經過了幾秒
              ────────────────────────────────────────
              部分: self.window_seconds - (current_time -
                oldest_timestamp)
              說明: 最舊請求還要幾秒才會離開視窗
              ────────────────────────────────────────
              部分: int(...)
              說明: 轉成整數（向下取整）
              ────────────────────────────────────────
              部分: + 1
              說明: 多加 1 秒（安全邊際）
              
              概念：最舊的請求時間戳記 + 視窗長度 = 這個請求「過期」的時間點
              
              為什麼要 + 1？
              原因 1：浮點數精度誤差
              # 假設計算結果是 0.1 秒
              retry_after = int(0.1)  # 會變成 0
              # +1 確保至少回傳 1 秒，而不是 0 秒（0 秒可能讓用戶以為可以立即重試）
            
              原因 2：HTTP Retry-After 標頭慣例
              - HTTP 規範建議 Retry-After 應該是正整數
              - 0 秒不符合語意（已經被拒絕了，不可能 0 秒後就能重試）
              - +1 提供保守的估計，避免用戶太早重試又被拒絕
            
              原因 3：時序問題
              - 現在時間是 120.0
              - 計算結果是 0.1 秒後可以重試
              - 但用戶收到回應、解析、發起新請求可能已經過了 0.2 秒
              - +1 確保有足夠緩衝
            """
            retry_after = int(self.window_seconds - (current_time - oldest_timestamp)) + 1
            return False, retry_after

    def _get_lock(self, ip_address: str) -> asyncio.Lock:
        """Get or create lock for this IP."""
        if ip_address not in self._locks:
            """
            進入全域鎖定的保護區塊, 確保同一時間只有一個執行緒能執行這個區塊內的程式碼
            為什麼需要：因為 self._locks 字典是共享資源，多個執行緒同時存取可能導致競爭條件
            """
            with self._global_lock:
                if ip_address not in self._locks:
                    self._locks[ip_address] = asyncio.Lock()
        return self._locks[ip_address]

    def _cleanup_old_entries(self, ip_address: str, current_time: float):
        """Remove timestamps outside the window."""
        cutoff = current_time - self.window_seconds
        timestamps = self._requests.get(ip_address, [])
        self._requests[ip_address] = [t for t in timestamps if t > cutoff]
