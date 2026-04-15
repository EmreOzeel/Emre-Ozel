"""Incident priority scoring and aging fields.

Revision ID: 017
Revises: 016
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "017"
down_revision: Union[str, None] = "016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("live_incidents") as batch:
        batch.add_column(sa.Column("priority_score", sa.Float, nullable=True))
        batch.add_column(sa.Column("last_activity_at", sa.DateTime, nullable=True))
        batch.add_column(sa.Column("decay_factor", sa.Float, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("live_incidents") as batch:
        batch.drop_column("decay_factor")
        batch.drop_column("last_activity_at")
        batch.drop_column("priority_score")
