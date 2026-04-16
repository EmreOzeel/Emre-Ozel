"""User-defined correlation rules table.

Revision ID: 023
Revises: 022
Create Date: 2026-04-15
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "023"
down_revision: Union[str, None] = "022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "correlation_rules",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("scope", sa.String, nullable=False, server_default="user"),
        # Condition
        sa.Column("condition_field", sa.String, nullable=False),
        sa.Column("condition_operator", sa.String, nullable=False),
        sa.Column("condition_value", sa.String, nullable=False),
        # Aggregation
        sa.Column("aggregation_type", sa.String, nullable=False),
        sa.Column("aggregation_field", sa.String, nullable=True),
        sa.Column("threshold", sa.Float, nullable=False),
        # Window & grouping
        sa.Column("time_window_minutes", sa.Integer, nullable=False, server_default="10"),
        sa.Column("target_entity", sa.String, nullable=False),
        # Incident creation
        sa.Column("severity", sa.String, nullable=False, server_default="medium"),
        sa.Column("incident_behavior_type", sa.String, nullable=False),
        sa.Column("cooldown_minutes", sa.Integer, nullable=False, server_default="30"),
        # Timestamps
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("correlation_rules")
