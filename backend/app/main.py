from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.db.session import engine


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    engine.dispose()


app = FastAPI(
    title="Sentinel Behavioral Security API",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/dependencies")
def dependency_health() -> dict[str, str]:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

    redis_client = redis.from_url(settings.redis_url)
    redis_client.ping()

    return {
        "database": "ok",
        "redis": "ok",
    }
