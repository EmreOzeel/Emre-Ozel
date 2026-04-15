"""Asset registry and incident impact fields.

Revision ID: 016
Revises: 015
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "016"
down_revision: Union[str, None] = "015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("ip_address", sa.String, nullable=False, unique=True, index=True),
        sa.Column("hostname", sa.String, nullable=True),
        sa.Column("asset_type", sa.String, nullable=False, server_default="workstation"),
        sa.Column("criticality", sa.String, nullable=False, server_default="low"),
        sa.Column("environment", sa.String, nullable=True),
        sa.Column("tags", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    with op.batch_alter_table("live_incidents") as batch:
        batch.add_column(sa.Column("impacted_assets_count", sa.Integer, nullable=True))
        batch.add_column(sa.Column("highest_target_criticality", sa.String, nullable=True))
        batch.add_column(sa.Column("target_summary", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("live_incidents") as batch:
        batch.drop_column("target_summary")
        batch.drop_column("highest_target_criticality")
        batch.drop_column("impacted_assets_count")
    op.drop_table("assets")
