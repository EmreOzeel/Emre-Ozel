"""Attack session intent and timeline fields.

Revision ID: 020
Revises: 019
Create Date: 2026-04-14
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "020"
down_revision: Union[str, None] = "019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.add_column(sa.Column("behavior_timeline", sa.Text, nullable=True))
        batch.add_column(sa.Column("behavior_sequence", sa.String, nullable=True))
        batch.add_column(sa.Column("attack_intent", sa.String, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("attack_sessions") as batch:
        batch.drop_column("attack_intent")
        batch.drop_column("behavior_sequence")
        batch.drop_column("behavior_timeline")
