"""Team sharing scope: teams table, user.team_id, scope/team_id/created_by/
updated_by columns on role presets and saved queries, scope + team_id on
path-analysis feedback, and a new investigation_notes table.

Revision ID: 003
Revises: 002
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── teams ────────────────────────────────────────────────────────────────
    op.create_table(
        "teams",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("name", sa.String, unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )

    # ── users.team_id ───────────────────────────────────────────────────────
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("team_id", sa.Integer, sa.ForeignKey("teams.id"), nullable=True))
    op.create_index("ix_users_team_id", "users", ["team_id"])

    # ── role presets: scope / team_id / created_by / updated_by ─────────────
    with op.batch_alter_table("path_analysis_role_presets") as batch:
        batch.add_column(sa.Column("scope", sa.String, nullable=False, server_default="private"))
        batch.add_column(sa.Column("team_id", sa.Integer, sa.ForeignKey("teams.id"), nullable=True))
        batch.add_column(sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True))
        batch.add_column(sa.Column("updated_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True))
    op.create_index(
        "ix_path_analysis_role_presets_scope", "path_analysis_role_presets", ["scope"]
    )
    op.create_index(
        "ix_path_analysis_role_presets_team_id", "path_analysis_role_presets", ["team_id"]
    )

    # ── saved queries: scope / team_id / created_by / updated_by ────────────
    with op.batch_alter_table("path_analysis_saved_queries") as batch:
        batch.add_column(sa.Column("scope", sa.String, nullable=False, server_default="private"))
        batch.add_column(sa.Column("team_id", sa.Integer, sa.ForeignKey("teams.id"), nullable=True))
        batch.add_column(sa.Column("created_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True))
        batch.add_column(sa.Column("updated_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True))
    op.create_index(
        "ix_path_analysis_saved_queries_scope", "path_analysis_saved_queries", ["scope"]
    )
    op.create_index(
        "ix_path_analysis_saved_queries_team_id", "path_analysis_saved_queries", ["team_id"]
    )

    # ── feedback: scope / team_id ───────────────────────────────────────────
    with op.batch_alter_table("path_analysis_feedback") as batch:
        batch.add_column(sa.Column("scope", sa.String, nullable=False, server_default="private"))
        batch.add_column(sa.Column("team_id", sa.Integer, sa.ForeignKey("teams.id"), nullable=True))
    op.create_index(
        "ix_path_analysis_feedback_scope", "path_analysis_feedback", ["scope"]
    )
    op.create_index(
        "ix_path_analysis_feedback_team_id", "path_analysis_feedback", ["team_id"]
    )

    # ── investigation_notes ─────────────────────────────────────────────────
    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column(
            "analysis_id",
            sa.String,
            sa.ForeignKey("analyses.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("source_ip", sa.String, nullable=False),
        sa.Column("destination_ip", sa.String, nullable=False),
        sa.Column("destination_port", sa.Integer, nullable=True),
        sa.Column("body", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "scope", sa.String, nullable=False, server_default="private", index=True
        ),
        sa.Column(
            "team_id", sa.Integer, sa.ForeignKey("teams.id"), nullable=True, index=True
        ),
        sa.Column(
            "created_by",
            sa.Integer,
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("updated_by", sa.Integer, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("investigation_notes")

    op.drop_index("ix_path_analysis_feedback_team_id", table_name="path_analysis_feedback")
    op.drop_index("ix_path_analysis_feedback_scope", table_name="path_analysis_feedback")
    with op.batch_alter_table("path_analysis_feedback") as batch:
        batch.drop_column("team_id")
        batch.drop_column("scope")

    op.drop_index(
        "ix_path_analysis_saved_queries_team_id",
        table_name="path_analysis_saved_queries",
    )
    op.drop_index(
        "ix_path_analysis_saved_queries_scope",
        table_name="path_analysis_saved_queries",
    )
    with op.batch_alter_table("path_analysis_saved_queries") as batch:
        batch.drop_column("updated_by")
        batch.drop_column("created_by")
        batch.drop_column("team_id")
        batch.drop_column("scope")

    op.drop_index(
        "ix_path_analysis_role_presets_team_id",
        table_name="path_analysis_role_presets",
    )
    op.drop_index(
        "ix_path_analysis_role_presets_scope",
        table_name="path_analysis_role_presets",
    )
    with op.batch_alter_table("path_analysis_role_presets") as batch:
        batch.drop_column("updated_by")
        batch.drop_column("created_by")
        batch.drop_column("team_id")
        batch.drop_column("scope")

    op.drop_index("ix_users_team_id", table_name="users")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("team_id")

    op.drop_table("teams")
