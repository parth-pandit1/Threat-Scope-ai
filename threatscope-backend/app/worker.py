"""
RQ worker entry point.
"""

import sys
from rq import Worker, Queue, Connection
from app.core.rq_setup import redis_conn

if __name__ == '__main__':
    # Provide the queue names to listen on via CLI args or default to 'default'
    queues = sys.argv[1:] or ['default']
    
    with Connection(redis_conn):
        w = Worker(queues)
        w.work(logging_level="INFO")
