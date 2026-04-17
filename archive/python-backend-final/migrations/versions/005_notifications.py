"""In-app notifications table for investigation workflow triggers.

Revision ID: 005
Revises: 004
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "user_id",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("type", sa.String, nullable=False, index=True),
        sa.Column(
            "analysis_id",
            sa.String,
            sa.ForeignKey("analyses.id"),
            nullable=True,
            index=True,
        ),
        sa.Column(
            "actor_user_id",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        sa.Column("message", sa.Text, nullable=False, server_default=""),
        sa.Column("read_at", sa.DateTime, nullable=True, index=True),
        sa.Column(
            "created_at", sa.DateTime, server_default=sa.func.now(), index=True
        ),
    )


def downgrade() -> None:
    op.drop_table("notifications")
