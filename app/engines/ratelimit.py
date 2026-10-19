"""Atomic rate-limit counters shared across workers and API instances.

Redis is the production backend (INCR + EXPIRE in a single pipeline — atomic
across all workers, not just one process). On a Redis outage the limiter
degrades to a per-process counter: slightly weaker across instances but far
better than no limit at all, and it keeps tests runnable without a broker.
"""

from __future__ import annotations

import logging
import threading
import time

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)

_client: redis.Redis | None = None
# When the broker is unreachable we skip retrying it for a short window —
# otherwise every limiter call pays the connect timeout (slow + log noise).
_backend_down_until = 0.0
_BACKEND_DOWN_GRACE_S = 30.0

_mem_lock = threading.Lock()
_mem: dict[str, tuple[float, int]] = {}


def _redis() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
    return _client


def _redis_down() -> bool:
    return time.time() < _backend_down_until


def _mark_redis_down() -> None:
    global _backend_down_until
    _backend_down_until = time.time() + _BACKEND_DOWN_GRACE_S
    logger.warning("rate limiter: Redis unavailable — per-process fallback for %ss",
                   _BACKEND_DOWN_GRACE_S)


def _mem_hit(key: str, window_s: int) -> int:
    now = time.time()
    with _mem_lock:
        expiry, count = _mem.get(key, (0.0, 0))
        if expiry <= now:
            count = 0
        count += 1
        _mem[key] = (now + window_s, count)
        return count


def hit(key: str, window_s: int) -> int:
    """Increment ``key`` inside a sliding window; returns the new count."""
    if not _redis_down():
        try:
            pipe = _redis().pipeline(transaction=True)
            pipe.incr(key)
            pipe.expire(key, window_s)
            return int(pipe.execute()[0])
        except redis.RedisError:
            _mark_redis_down()
    return _mem_hit(key, window_s)


def acquire_once(key: str, ttl_s: int) -> bool:
    """SET NX EX — true only for the first caller inside ``ttl_s`` (cooldown)."""
    if ttl_s <= 0:
        return True
    if not _redis_down():
        try:
            return bool(_redis().set(key, "1", nx=True, ex=ttl_s))
        except redis.RedisError:
            _mark_redis_down()
    now = time.time()
    with _mem_lock:
        expiry, _ = _mem.get(key, (0.0, 0))
        if expiry > now:
            return False
        _mem[key] = (now + ttl_s, 1)
        return True


def _reset_mem() -> None:
    """Test hook: clear the in-process fallback counters."""
    global _backend_down_until
    with _mem_lock:
        _mem.clear()
        _backend_down_until = float("inf")  # tests stay on the in-memory backend
