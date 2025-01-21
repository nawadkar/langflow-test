"""add auth0 fields

Revision ID: 2024_01_21_add_auth0_fields
Revises: e3162c1804e6
Create Date: 2024-01-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision: str = '2024_01_21_add_auth0_fields'
down_revision: Union[str, None] = 'e3162c1804e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add auth0_user_id column
    op.add_column('user', sa.Column('auth0_user_id', sa.String(), nullable=True))
    op.create_index(op.f('ix_user_auth0_user_id'), 'user', ['auth0_user_id'], unique=False)

    # Add email column
    op.add_column('user', sa.Column('email', sa.String(), nullable=True))
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=False)

    # Modify password column to be nullable
    with op.batch_alter_table('user') as batch_op:
        batch_op.alter_column('password',
                            existing_type=sa.String(),
                            nullable=True)

def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_index(op.f('ix_user_auth0_user_id'), table_name='user')

    # Drop columns
    op.drop_column('user', 'email')
    op.drop_column('user', 'auth0_user_id')

    # Make password non-nullable again
    with op.batch_alter_table('user') as batch_op:
        batch_op.alter_column('password',
                            existing_type=sa.String(),
                            nullable=False)
