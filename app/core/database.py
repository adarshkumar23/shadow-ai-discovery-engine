"""
Database session and engine configuration.

SQLAlchemy 2.0 SYNC engine with explicit pool configuration.
Integration seam 1: own engine now, Depends(get_db) later.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_timeout=30,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session.

    At integration time, this becomes CompliVibe's get_db dependency.
    No change to function signature.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
