#!/bin/sh
set -e

echo "Running database migrations (alembic upgrade head)..."
alembic upgrade head

echo "Database migrations complete. Starting command: $@"
exec "$@"
