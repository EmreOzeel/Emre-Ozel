"""Live behavior incidents.

Revision ID: 014
Revises: 013
Create Date: 2026-04-13
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "014"
down_revision: Union[str, None] = "013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "live_incidents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_ip", sa.String, nullable=False, index=True),
        sa.Column("behavior_type", sa.String, nullable=False, index=True),
        sa.Column("severity", sa.String, nullable=False, server_default="low", index=True),
        sa.Column("status", sa.String, nullable=False, server_default="open", index=True),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("linked_flow_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("latest_confidence", sa.Float, nullable=True),
        sa.Column("summary", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("live_incidents")
