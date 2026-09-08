from contextlib import asynccontextmanager
from sqlalchemy import text

import redis
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import engine, SessionLocal, init_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield
    engine.dispose()


app = FastAPI(
    title="Sentinel Behavioral Security API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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


@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user_in: UserCreate, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    db_user = User(email=user_in.email, full_name=user_in.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).all()
