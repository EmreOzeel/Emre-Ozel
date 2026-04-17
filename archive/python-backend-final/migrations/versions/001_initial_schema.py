"""Initial schema: users, analyses, suppression_rules, finding_triage

Revision ID: 001
Revises:
Create Date: 2026-04-01
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("username", sa.String, unique=True, nullable=False),
        sa.Column("hashed_password", sa.String, nullable=False),
        sa.Column("is_admin", sa.Boolean, default=False, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "analyses",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("filename", sa.String, nullable=False),
        sa.Column("file_path", sa.String, nullable=True),
        sa.Column("file_hash", sa.String, nullable=True, index=True),
        sa.Column("status", sa.String, default="pending"),
        sa.Column("current_stage", sa.String, nullable=True),
        sa.Column("progress_pct", sa.Integer, default=0),
        sa.Column("packet_count", sa.Integer, default=0),
        sa.Column("issue_count", sa.Integer, default=0),
        sa.Column("critical_count", sa.Integer, default=0),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("result_json", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("finished_at", sa.DateTime, nullable=True),
    )

    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("scope", sa.String, default="user", nullable=False),
        sa.Column("rule_id", sa.String, nullable=True),
        sa.Column("src_ip", sa.String, nullable=True),
        sa.Column("dst_ip", sa.String, nullable=True),
        sa.Column("analysis_id", sa.String, sa.ForeignKey("analyses.id"), nullable=True),
        sa.Column("reason", sa.String, nullable=False, default=""),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "finding_triage",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("analysis_id", sa.String, sa.ForeignKey("analyses.id"), nullable=False, index=True),
        sa.Column("finding_key", sa.String, nullable=False, index=True),
        sa.Column("status", sa.String, default="new", nullable=False),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("analyst_id", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("finding_triage")
    op.drop_table("suppression_rules")
    op.drop_table("analyses")
    op.drop_table("users")
