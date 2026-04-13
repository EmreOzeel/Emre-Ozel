"""Historical run records for path monitors (trend intelligence).

Adds the ``monitored_path_runs`` table.

Revision ID: 007
Revises: 006
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "monitored_path_runs",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "monitored_path_id",
            sa.Integer,
            sa.ForeignKey("monitored_paths.id"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "run_at", sa.DateTime,
            server_default=sa.func.now(), nullable=False, index=True,
        ),
        sa.Column("connection_outcome", sa.String, nullable=False),
        sa.Column("primary_impairment", sa.String, nullable=True),
        sa.Column(
            "path_confidence_score", sa.Integer,
            nullable=False, server_default="0",
        ),
        sa.Column(
            "drift_severity", sa.String,
            nullable=False, server_default="none",
        ),
        sa.Column(
            "action_required", sa.Boolean,
            nullable=False, server_default=sa.false(),
        ),
        sa.Column("timing_json", sa.Text, nullable=True),
        sa.Column("impairments_json", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("monitored_path_runs")
