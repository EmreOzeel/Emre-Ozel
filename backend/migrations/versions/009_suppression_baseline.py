"""Monitor-level suppression rules and baseline expectations.

Adds ``monitor_suppressions`` table and ``baseline_json`` column on
``monitored_paths``.

Revision ID: 009
Revises: 008
Create Date: 2026-04-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitor_suppressions",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "monitored_path_id",
            sa.Integer,
            sa.ForeignKey("monitored_paths.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("kind", sa.String, nullable=False),
        sa.Column("value", sa.String, nullable=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column(
            "enabled", sa.Boolean,
            nullable=False, server_default=sa.true(),
        ),
        sa.Column("until", sa.DateTime, nullable=True),
        sa.Column(
            "created_by", sa.Integer,
            sa.ForeignKey("users.id"), nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime, server_default=sa.func.now(),
        ),
    )
    with op.batch_alter_table("monitored_paths") as batch:
        batch.add_column(sa.Column("baseline_json", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("monitored_paths") as batch:
        batch.drop_column("baseline_json")
    op.drop_table("monitor_suppressions")
