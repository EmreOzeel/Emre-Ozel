"""GeoIP cache table.

Revision ID: 025
Revises: 024
Create Date: 2026-04-15
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "025"
down_revision: Union[str, None] = "024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "geoip_cache",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("ip", sa.String, nullable=False, unique=True, index=True),
        sa.Column("country_code", sa.String, nullable=True),
        sa.Column("country_name", sa.String, nullable=True),
        sa.Column("city", sa.String, nullable=True),
        sa.Column("latitude", sa.Float, nullable=True),
        sa.Column("longitude", sa.Float, nullable=True),
        sa.Column("asn", sa.Integer, nullable=True),
        sa.Column("asn_org", sa.String, nullable=True),
        sa.Column("is_private", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("is_bogon", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("source", sa.String, nullable=False),
        sa.Column("looked_up_at", sa.DateTime, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("geoip_cache")
