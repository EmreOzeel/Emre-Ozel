"""Attack session enrichment fields.

Revision ID: 019
Revises: 018
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "019"
down_revision: Union[str, None] = "018"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.add_column(sa.Column("top_destination_ips", sa.Text, nullable=True))
        batch.add_column(sa.Column("top_ports", sa.Text, nullable=True))
        batch.add_column(sa.Column("target_summary", sa.Text, nullable=True))
        batch.add_column(sa.Column("highest_target_criticality", sa.String, nullable=True))
        batch.add_column(sa.Column("session_summary", sa.Text, nullable=True))
        batch.add_column(sa.Column("recommended_next_step", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.drop_column("recommended_next_step")
        batch.drop_column("session_summary")
        batch.drop_column("highest_target_criticality")
        batch.drop_column("target_summary")
        batch.drop_column("top_ports")
        batch.drop_column("top_destination_ips")
