"""Initial migration

Revision ID: 001_initial_migration
Revises: None
Create Date: 2026-07-26 19:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial_migration'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('scan_type', sa.Enum('FILE', 'URL', 'IP', name='scantype'), nullable=False),
        sa.Column('target', sa.String(length=2048), nullable=False),
        sa.Column('file_hash_md5', sa.String(length=32), nullable=True),
        sa.Column('file_hash_sha256', sa.String(length=64), nullable=True),
        sa.Column('status', sa.Enum('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', name='scanstatus'), nullable=False),
        sa.Column('threat_score', sa.Integer(), nullable=True),
        sa.Column('verdict', sa.Enum('CLEAN', 'LOW_RISK', 'SUSPICIOUS', 'MALICIOUS', name='verdict'), nullable=True),
        sa.Column('result_json', postgresql.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_table('scans')
