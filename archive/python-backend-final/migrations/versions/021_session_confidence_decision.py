"""Attack session confidence and decision engine fields.

Revision ID: 021
Revises: 020
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "021"
down_revision: Union[str, None] = "020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.add_column(sa.Column("attack_intents", sa.Text, nullable=True))
        batch.add_column(sa.Column("intent_confidence", sa.Float, nullable=True))
        batch.add_column(sa.Column("activity_rate", sa.Float, nullable=True))
        batch.add_column(sa.Column("burst_flag", sa.Boolean, nullable=True, server_default="0"))
        batch.add_column(sa.Column("recommended_action", sa.String, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.drop_column("recommended_action")
        batch.drop_column("burst_flag")
        batch.drop_column("activity_rate")
        batch.drop_column("intent_confidence")
        batch.drop_column("attack_intents")
