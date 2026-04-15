"""Attack session correlation table.

Revision ID: 018
Revises: 017
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "018"
down_revision: Union[str, None] = "017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_sessions",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("source_ip", sa.String, nullable=False, index=True),
        sa.Column("start_time", sa.DateTime, nullable=False),
        sa.Column("last_activity", sa.DateTime, nullable=False),
        sa.Column("incident_ids", sa.Text, nullable=False, server_default="[]"),
        sa.Column("behaviors", sa.Text, nullable=False, server_default="[]"),
        sa.Column("severity", sa.String, nullable=False, server_default="low"),
        sa.Column("priority_score", sa.Float, nullable=False, server_default="0"),
        sa.Column("status", sa.String, nullable=False, server_default="active", index=True),
        sa.Column("total_incidents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_destinations", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_ports", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("attack_sessions")
