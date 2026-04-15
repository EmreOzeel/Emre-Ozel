"""Enrichment fields on live_incidents.

Revision ID: 015
Revises: 014
Create Date: 2026-04-13
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "015"
down_revision: Union[str, None] = "014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("live_incidents") as batch:
        batch.add_column(sa.Column("top_destination_ips", sa.Text, nullable=True))
        batch.add_column(sa.Column("top_ports", sa.Text, nullable=True))
        batch.add_column(sa.Column("total_distinct_destinations", sa.Integer, nullable=True))
        batch.add_column(sa.Column("total_distinct_ports", sa.Integer, nullable=True))
        batch.add_column(sa.Column("sample_flows", sa.Text, nullable=True))
        batch.add_column(sa.Column("last_activity_summary", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("live_incidents") as batch:
        batch.drop_column("last_activity_summary")
        batch.drop_column("sample_flows")
        batch.drop_column("total_distinct_ports")
        batch.drop_column("total_distinct_destinations")
        batch.drop_column("top_ports")
        batch.drop_column("top_destination_ips")
