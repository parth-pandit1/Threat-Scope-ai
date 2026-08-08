"""
Rate limiter configuration module.
Provides user-aware key functions and dynamic tier-based rate limits.
"""

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


def get_user_or_ip_key(request: Request) -> str:
    """
    Returns a unique rate limiting key for the request.
    If the request state contains an authenticated user, uses the user's ID and tier.
    Otherwise, falls back to the client's remote IP address.
    """
    user = getattr(request.state, "user", None)
    if user:
        return f"user:{user.id}:{user.tier.value}"
    return f"ip:{get_remote_address(request)}"


def get_rate_limit(key: str) -> str:
    """
    Returns the rate limit ceiling string dynamically based on user tier encoded in key.
    - Pro tier: 100 requests per hour
    - Free tier: 20 requests per hour
    - Anonymous (no login): 10 requests per hour
    """
    if key.startswith("user:"):
        parts = key.split(":")
        if len(parts) >= 3 and parts[2] == "pro":
            return "100/hour"
        return "20/hour"
    return "10/hour"


limiter = Limiter(key_func=get_user_or_ip_key)
