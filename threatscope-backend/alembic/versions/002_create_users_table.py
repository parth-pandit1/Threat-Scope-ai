"""create users table

Revision ID: 002_create_users_table
Revises: 001_initial_migration
Create Date: 2026-07-27 11:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_create_users_table'
down_revision: Union[str, None] = '001_initial_migration'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('api_key', sa.String(length=255), nullable=False),
        sa.Column('tier', sa.Enum('FREE', 'PRO', name='usertier'), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_banned', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_api_key'), 'users', ['api_key'], unique=True)

    # 3. Add foreign key on scans table
    op.create_foreign_key(
        'fk_scans_user_id_users',
        'scans', 'users',
        ['user_id'], ['id'],
        ondelete='SET NULL'
    )


def downgrade() -> None:
    # 1. Remove foreign key constraint
    op.drop_constraint('fk_scans_user_id_users', 'scans', type_='foreignkey')

    # 2. Drop users table
    op.drop_index(op.f('ix_users_api_key'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

    # 3. Drop enum usertier
    user_tier_enum = sa.Enum('FREE', 'PRO', name='usertier')
    user_tier_enum.drop(op.get_bind(), checkfirst=True)
