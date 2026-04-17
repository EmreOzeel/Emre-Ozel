"""Analyst outcomes for monitored paths (feedback loop).

Adds ``monitor_outcomes`` table and ``last_outcome`` / ``last_outcome_at``
columns on ``monitored_paths``.

Revision ID: 008
Revises: 007
Create Date: 2026-04-12
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitor_outcomes",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "monitored_path_id",
            sa.Integer,
            sa.ForeignKey("monitored_paths.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("outcome", sa.String, nullable=False, index=True),
        sa.Column("root_cause_type", sa.String, nullable=True),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("signal_drivers_json", sa.Text, nullable=True),
        sa.Column(
            "analyst_id",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "created_at", sa.DateTime,
            server_default=sa.func.now(), index=True,
        ),
    )
    with op.batch_alter_table("monitored_paths") as batch:
        batch.add_column(sa.Column("last_outcome", sa.String, nullable=True))
        batch.add_column(sa.Column("last_outcome_at", sa.DateTime, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("monitored_paths") as batch:
        batch.drop_column("last_outcome_at")
        batch.drop_column("last_outcome")
    op.drop_table("monitor_outcomes")
