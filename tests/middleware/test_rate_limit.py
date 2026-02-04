import asyncio

import pytest
from app.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_allows_under_limit():
    """Test requests under limit are allowed."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    for _ in range(5):
        allowed, retry = await limiter.check_rate_limit("192.168.1.1")
        assert allowed is True
        assert retry is None


@pytest.mark.asyncio
async def test_rate_limiter_blocks_over_limit():
    """Test requests over limit are blocked."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)
    for _ in range(5):
        await limiter.check_rate_limit("192.168.1.1")

    allowed, retry = await limiter.check_rate_limit("192.168.1.1")
    assert allowed is False
    assert retry is not None
    assert retry > 0


@pytest.mark.asyncio
async def test_rate_limiter_resets_after_window():
    """Test counter resets after window expires."""
    limiter = RateLimiter(max_requests=5, window_seconds=1)
    for _ in range(5):
        await limiter.check_rate_limit("192.168.1.1")

    # Should be blocked
    allowed, _ = await limiter.check_rate_limit("192.168.1.1")
    assert allowed is False

    # Wait for window to expire
    await asyncio.sleep(1.1)

    # Should be allowed again
    allowed, _ = await limiter.check_rate_limit("192.168.1.1")
    assert allowed is True


@pytest.mark.asyncio
async def test_different_ips_independent():
    """Test different IPs have independent counters."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)

    # IP 1 exhausts its quota
    for _ in range(5):
        await limiter.check_rate_limit("192.168.1.1")

    # IP 1 should be blocked
    allowed, _ = await limiter.check_rate_limit("192.168.1.1")
    assert allowed is False

    # IP 2 should still work
    allowed, _ = await limiter.check_rate_limit("192.168.1.2")
    assert allowed is True


@pytest.mark.asyncio
async def test_cleanup_old_entries():
    """Test old timestamps are cleaned up."""
    limiter = RateLimiter(max_requests=10, window_seconds=1)

    # Make 5 requests
    for _ in range(5):
        await limiter.check_rate_limit("192.168.1.1")

    # Should have 5 entries
    assert len(limiter._requests["192.168.1.1"]) == 5

    # Wait for window to expire
    await asyncio.sleep(1.1)

    # Make another request, which should clean up old entries
    await limiter.check_rate_limit("192.168.1.1")

    # Should have only 1 entry (the new request)
    assert len(limiter._requests["192.168.1.1"]) == 1


@pytest.mark.asyncio
async def test_retry_after_calculation():
    """Test retry_after is calculated correctly."""
    limiter = RateLimiter(max_requests=5, window_seconds=60)

    # Exhaust the limit
    for _ in range(5):
        await limiter.check_rate_limit("192.168.1.1")

    # Next request should be blocked
    allowed, retry_after = await limiter.check_rate_limit("192.168.1.1")
    assert allowed is False
    # retry_after should be close to 60 seconds
    assert 55 <= retry_after <= 61


@pytest.mark.asyncio
async def test_rate_limiter_handles_unknown_ip():
    """Test rate limiter handles 'unknown' IP address."""
    limiter = RateLimiter(max_requests=3, window_seconds=60)

    for _ in range(3):
        allowed, _ = await limiter.check_rate_limit("unknown")
        assert allowed is True

    # 4th request should be blocked
    allowed, _ = await limiter.check_rate_limit("unknown")
    assert allowed is False
