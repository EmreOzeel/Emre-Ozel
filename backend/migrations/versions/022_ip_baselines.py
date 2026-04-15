"""IP baseline learning table.

Revision ID: 022
Revises: 021
Create Date: 2026-04-15
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "022"
down_revision: Union[str, None] = "021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_baselines",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("source_ip", sa.String, nullable=False, unique=True, index=True),
        sa.Column("observation_window_days", sa.Integer, nullable=False, server_default="7"),
        sa.Column("sample_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("avg_flows_per_window", sa.Float, nullable=False, server_default="0"),
        sa.Column("avg_distinct_destinations", sa.Float, nullable=False, server_default="0"),
        sa.Column("avg_distinct_ports", sa.Float, nullable=False, server_default="0"),
        sa.Column("avg_deny_ratio", sa.Float, nullable=False, server_default="0"),
        sa.Column("avg_reset_ratio", sa.Float, nullable=False, server_default="0"),
        sa.Column("avg_bytes_per_flow", sa.Float, nullable=False, server_default="0"),
        sa.Column("stddev_flows", sa.Float, nullable=False, server_default="0"),
        sa.Column("stddev_deny_ratio", sa.Float, nullable=False, server_default="0"),
        sa.Column("stddev_reset_ratio", sa.Float, nullable=False, server_default="0"),
        sa.Column("last_computed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("ip_baselines")
