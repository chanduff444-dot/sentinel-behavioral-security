"""add risk score to events

Revision ID: 001
Revises: 
Create Date: 2026-09-08

"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("events", sa.Column("risk_score", sa.Float(), nullable=True))
    op.create_index("ix_events_risk_score", "events", ["risk_score"])


def downgrade():
    op.drop_index("ix_events_risk_score", "events")
    op.drop_column("events", "risk_score")
