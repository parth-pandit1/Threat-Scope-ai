import redis
from rq import Queue
from app.core.config import settings

# Create a Redis connection
redis_conn = redis.from_url(settings.REDIS_URL)

def get_queue(name: str = 'default') -> Queue:
    """Get an RQ queue by name."""
    return Queue(name, connection=redis_conn)
