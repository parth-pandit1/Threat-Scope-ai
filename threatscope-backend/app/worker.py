"""
RQ worker entry point.
"""

import sys
from rq import Worker, Connection
from app.core.rq_setup import redis_conn

if __name__ == '__main__':
    # Check for burst mode argument
    burst = False
    args = sys.argv[1:]
    if '--burst' in args:
        burst = True
        args.remove('--burst')
        
    # Provide the queue names to listen on via CLI args or default to 'default'
    queues = args or ['default']
    
    with Connection(redis_conn):
        w = Worker(queues)
        w.work(logging_level="INFO", burst=burst)
