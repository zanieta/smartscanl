import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from .models import Base

load_dotenv()


def make_engine(database_url: str | None):
    """Build the PostgreSQL engine. SQLite has been retired — PostgreSQL is the
    only supported backend, so a missing or non-Postgres DATABASE_URL is a
    startup error (fail fast) rather than a silent SQLite fallback."""
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is required and must point to PostgreSQL "
            "(e.g. postgresql+psycopg://user:pass@host:5432/vulnsense). "
            "SQLite is no longer supported."
        )
    if not database_url.startswith(("postgresql", "postgres")):
        raise RuntimeError(
            f"DATABASE_URL must be a PostgreSQL URL; got {database_url.split(':', 1)[0]!r}. "
            "SQLite is no longer supported."
        )
    return create_engine(database_url, pool_pre_ping=True, pool_size=5,
                         max_overflow=5)


engine = make_engine(os.getenv("DATABASE_URL"))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
