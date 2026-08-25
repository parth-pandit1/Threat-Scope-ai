"""
Rate limiter configuration module.
Provides IP-based rate limiting for public scan endpoints.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address


def get_rate_limit(_key: str) -> str:
    """
    Returns the rate limit ceiling string.
    All requests are limited to 10 per hour per IP since scanning is fully public.
    """
    return "10/hour"


limiter = Limiter(key_func=get_remote_address)
