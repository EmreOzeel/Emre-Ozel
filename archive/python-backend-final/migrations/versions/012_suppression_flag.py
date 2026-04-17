"""Add boolean suppressed flag to live_events and live_flows.

Revision ID: 012
Revises: 011
Create Date: 2026-04-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "012"
down_revision: Union[str, None] = "011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("live_events") as batch:
        batch.add_column(
            sa.Column("suppressed", sa.Boolean, nullable=True, server_default=sa.false())
        )
    with op.batch_alter_table("live_flows") as batch:
        batch.add_column(
            sa.Column("suppressed", sa.Boolean, nullable=True, server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table("live_flows") as batch:
        batch.drop_column("suppressed")
    with op.batch_alter_table("live_events") as batch:
        batch.drop_column("suppressed")
