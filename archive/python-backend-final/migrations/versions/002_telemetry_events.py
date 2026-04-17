"""Add telemetry_events table

Revision ID: 002
Revises: 001
Create Date: 2026-04-01
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("event_type", sa.String, nullable=False, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("properties_json", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now(), index=True),
    )


def downgrade() -> None:
    op.drop_table("telemetry_events")
