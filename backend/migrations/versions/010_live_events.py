"""Normalized live network events table for the ingestion layer.

Revision ID: 010
Revises: 009
Create Date: 2026-04-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "live_events",
        sa.Column("id", sa.Integer, primary_key=True),
        # Source identification
        sa.Column("source_id", sa.String, nullable=False, index=True),
        sa.Column("device_type", sa.String, nullable=False, index=True),
        sa.Column("device_role", sa.String, nullable=True),
        sa.Column("parser_id", sa.String, nullable=False),
        # Timing
        sa.Column("event_time", sa.DateTime, nullable=False, index=True),
        sa.Column(
            "received_at", sa.DateTime,
            server_default=sa.func.now(), nullable=False,
        ),
        # 5-tuple
        sa.Column("source_ip", sa.String, nullable=False, index=True),
        sa.Column("destination_ip", sa.String, nullable=False, index=True),
        sa.Column("source_port", sa.Integer, nullable=True),
        sa.Column("destination_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String, nullable=True),
        # Verdict
        sa.Column("action", sa.String, nullable=False, index=True),
        sa.Column("reason", sa.String, nullable=True),
        # Volume
        sa.Column("bytes_in", sa.Integer, nullable=True),
        sa.Column("bytes_out", sa.Integer, nullable=True),
        sa.Column("packets_in", sa.Integer, nullable=True),
        sa.Column("packets_out", sa.Integer, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        # NAT
        sa.Column("nat_source_ip", sa.String, nullable=True),
        sa.Column("nat_destination_ip", sa.String, nullable=True),
        sa.Column("nat_source_port", sa.Integer, nullable=True),
        sa.Column("nat_destination_port", sa.Integer, nullable=True),
        # Application
        sa.Column("application", sa.String, nullable=True),
        sa.Column("service", sa.String, nullable=True),
        # LB-specific
        sa.Column("backend_ip", sa.String, nullable=True),
        sa.Column("backend_port", sa.Integer, nullable=True),
        sa.Column("response_time_ms", sa.Float, nullable=True),
        sa.Column("health_status", sa.String, nullable=True),
        # Raw
        sa.Column("raw_line", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("live_events")
