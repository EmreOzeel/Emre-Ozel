"""Behavioral classification fields on live_flows.

Revision ID: 013
Revises: 012
Create Date: 2026-04-13
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "013"
down_revision: Union[str, None] = "012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("live_flows") as batch:
        batch.add_column(sa.Column("flow_type", sa.String, nullable=True, index=True))
        batch.add_column(sa.Column("reset_ratio", sa.Float, nullable=True))
        batch.add_column(sa.Column("deny_ratio", sa.Float, nullable=True))
        batch.add_column(sa.Column("burst_score", sa.Float, nullable=True))
        batch.add_column(sa.Column("asymmetric_behavior", sa.Boolean, nullable=True, server_default=sa.false()))
        batch.add_column(sa.Column("suspicious_reasons", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("live_flows") as batch:
        batch.drop_column("suspicious_reasons")
        batch.drop_column("asymmetric_behavior")
        batch.drop_column("burst_score")
        batch.drop_column("deny_ratio")
        batch.drop_column("reset_ratio")
        batch.drop_column("flow_type")
