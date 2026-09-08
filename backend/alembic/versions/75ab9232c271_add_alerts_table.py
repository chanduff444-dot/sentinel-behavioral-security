"""add alerts table

Revision ID: 75ab9232c271
Revises: 001
Create Date: 2026-09-08

"""
from alembic import op
import sqlalchemy as sa

revision = "75ab9232c271"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_id", "alerts", ["id"])
    op.create_index("ix_alerts_user_id", "alerts", ["user_id"])
    op.create_index("ix_alerts_event_id", "alerts", ["event_id"])


def downgrade():
    op.drop_index("ix_alerts_event_id", "alerts")
    op.drop_index("ix_alerts_user_id", "alerts")
    op.drop_index("ix_alerts_id", "alerts")
    op.drop_table("alerts")
