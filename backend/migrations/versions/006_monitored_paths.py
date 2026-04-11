"""Scheduled path monitoring + drift detection.

Adds the ``monitored_paths`` table.

Revision ID: 006
Revises: 005
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitored_paths",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "saved_query_id",
            sa.Integer,
            sa.ForeignKey("path_analysis_saved_queries.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "analysis_id",
            sa.String,
            sa.ForeignKey("analyses.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "owner_user_id",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "schedule_interval_minutes",
            sa.Integer,
            nullable=False,
            server_default="60",
        ),
        sa.Column(
            "enabled",
            sa.Boolean,
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("last_change_at", sa.DateTime, nullable=True),
        sa.Column("last_result_json", sa.Text, nullable=True),
        sa.Column("last_change_summary", sa.Text, nullable=True),
        sa.Column("last_drift_severity", sa.String, nullable=True),
        sa.Column(
            "created_at", sa.DateTime, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime, server_default=sa.func.now()
        ),
    )


def downgrade() -> None:
    op.drop_table("monitored_paths")
