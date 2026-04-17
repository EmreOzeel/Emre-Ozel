"""Reconstructed flow/session summaries from live events.

Revision ID: 011
Revises: 010
Create Date: 2026-04-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "live_flows",
        sa.Column("id", sa.Integer, primary_key=True),
        # Source identification
        sa.Column("source_id", sa.String, nullable=False, index=True),
        sa.Column("device_type", sa.String, nullable=False),
        sa.Column("device_role", sa.String, nullable=True),
        sa.Column("parser_id", sa.String, nullable=False),
        # 5-tuple
        sa.Column("source_ip", sa.String, nullable=False, index=True),
        sa.Column("destination_ip", sa.String, nullable=False, index=True),
        sa.Column("source_port", sa.Integer, nullable=True),
        sa.Column("destination_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String, nullable=True, index=True),
        # Timing
        sa.Column("first_seen", sa.DateTime, nullable=False, index=True),
        sa.Column("last_seen", sa.DateTime, nullable=False, index=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        # Counters
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_bytes_in", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_bytes_out", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_packets_in", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_packets_out", sa.Integer, nullable=False, server_default="0"),
        # Action counters
        sa.Column("allow_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("deny_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("drop_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("reset_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("alert_count", sa.Integer, nullable=False, server_default="0"),
        # Derived
        sa.Column("action_summary", sa.String, nullable=True),
        sa.Column("reason_summary", sa.String, nullable=True),
        # NAT
        sa.Column("nat_source_ip", sa.String, nullable=True),
        sa.Column("nat_destination_ip", sa.String, nullable=True),
        sa.Column("nat_source_port", sa.Integer, nullable=True),
        sa.Column("nat_destination_port", sa.Integer, nullable=True),
        # Application
        sa.Column("application", sa.String, nullable=True),
        sa.Column("service", sa.String, nullable=True),
        sa.Column("backend_ip", sa.String, nullable=True),
        sa.Column("backend_port", sa.Integer, nullable=True),
        # State
        sa.Column("state", sa.String, nullable=False, server_default="active", index=True),
        sa.Column("raw_event_count", sa.Integer, nullable=False, server_default="0"),
        # Timestamps
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("live_flows")
