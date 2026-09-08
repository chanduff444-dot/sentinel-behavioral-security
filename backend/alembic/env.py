from alembic import context
from sqlalchemy import engine_from_config

config = context.config
config.set_main_option("sqlalchemy.url", "postgresql://sentinel:sentinel_pass@db:5432/sentinel")

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models import Base  # noqa

def run_migrations_online():
    connectable = engine_from_config(
        {"sqlalchemy.url": config.get_main_option("sqlalchemy.url")},
        prefix="sqlalchemy.",
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()

run_migrations_online()
