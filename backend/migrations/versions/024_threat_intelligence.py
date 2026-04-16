"""Threat intelligence indicators and feeds tables.

Revision ID: 024
Revises: 023
Create Date: 2026-04-15
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "024"
down_revision: Union[str, None] = "023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("indicator_type", sa.String, nullable=False),
        sa.Column("indicator_value", sa.String, nullable=False, index=True),
        sa.Column("threat_type", sa.String, nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("source_feed", sa.String, nullable=False),
        sa.Column("first_seen", sa.DateTime, nullable=False),
        sa.Column("last_seen", sa.DateTime, nullable=False),
        sa.Column("expiry", sa.DateTime, nullable=True),
        sa.Column("tags", sa.Text, nullable=True),
        sa.Column("raw_data", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "threat_feeds",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("name", sa.String, unique=True, nullable=False),
        sa.Column("feed_type", sa.String, nullable=False),
        sa.Column("url", sa.String, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("last_fetched_at", sa.DateTime, nullable=True),
        sa.Column("last_indicator_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("fetch_interval_hours", sa.Integer, nullable=False, server_default="24"),
        sa.Column("format", sa.String, nullable=False, server_default="plain"),
        sa.Column("comment_char", sa.String, nullable=False, server_default="#"),
        sa.Column("ip_column", sa.Integer, nullable=False, server_default="0"),
        sa.Column("default_threat_type", sa.String, nullable=False, server_default="unknown"),
        sa.Column("default_confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("threat_feeds")
    op.drop_table("threat_indicators")
