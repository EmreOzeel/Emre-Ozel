"""Add PCAP trigger link columns to live_incidents.

Revision ID: 026
Revises: 025
Create Date: 2026-04-16
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "026"
down_revision: Union[str, None] = "025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("live_incidents", sa.Column(
        "linked_pcap_analysis_ids", sa.Text, nullable=True, server_default="[]",
    ))
    op.add_column("live_incidents", sa.Column(
        "pcap_trigger_count", sa.Integer, nullable=True, server_default="0",
    ))


def downgrade() -> None:
    op.drop_column("live_incidents", "pcap_trigger_count")
    op.drop_column("live_incidents", "linked_pcap_analysis_ids")
