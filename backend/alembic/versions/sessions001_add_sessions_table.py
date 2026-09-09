"""add sessions table

Revision ID: sessions001
Revises: 75ab9232c271
Create Date: 2026-09-08

"""
from alembic import op
import sqlalchemy as sa

revision = "sessions001"
down_revision = "75ab9232c271"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name="fk_sessions_user_id"),
    )
    op.create_index("ix_sessions_id", "sessions", ["id"])
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_session_id", "sessions", ["session_id"])


def downgrade():
    op.drop_constraint("fk_sessions_user_id", "sessions", type_="foreignkey")
    op.drop_index("ix_sessions_session_id", "sessions")
    op.drop_index("ix_sessions_user_id", "sessions")
    op.drop_index("ix_sessions_id", "sessions")
    op.drop_table("sessions")
