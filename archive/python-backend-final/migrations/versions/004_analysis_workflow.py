"""Investigation workflow fields on analyses: workflow_state, assigned_user_id,
workflow_updated_at, workflow_updated_by.

Revision ID: 004
Revises: 003
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("analyses") as batch:
        batch.add_column(
            sa.Column(
                "workflow_state",
                sa.String,
                nullable=False,
                server_default="new",
            )
        )
        batch.add_column(
            sa.Column(
                "assigned_user_id",
                sa.Integer,
                sa.ForeignKey("users.id"),
                nullable=True,
            )
        )
        batch.add_column(sa.Column("workflow_updated_at", sa.DateTime, nullable=True))
        batch.add_column(
            sa.Column(
                "workflow_updated_by",
                sa.Integer,
                sa.ForeignKey("users.id"),
                nullable=True,
            )
        )
    op.create_index("ix_analyses_workflow_state", "analyses", ["workflow_state"])
    op.create_index("ix_analyses_assigned_user_id", "analyses", ["assigned_user_id"])


def downgrade() -> None:
    op.drop_index("ix_analyses_assigned_user_id", table_name="analyses")
    op.drop_index("ix_analyses_workflow_state", table_name="analyses")
    with op.batch_alter_table("analyses") as batch:
        batch.drop_column("workflow_updated_by")
        batch.drop_column("workflow_updated_at")
        batch.drop_column("assigned_user_id")
        batch.drop_column("workflow_state")
