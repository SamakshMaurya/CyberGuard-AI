"""
CyberGuard AI — Database Module

Standard SQLite setup with an AsyncSessionWrapper for seamless async FastAPI
operations without requiring external C-extensions like greenlet.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

from config import settings

# Clean sqlite URL if it has aiosqlite prefix
db_url = settings.DATABASE_URL
if "+aiosqlite" in db_url:
    db_url = db_url.replace("+aiosqlite", "")

engine = create_engine(
    db_url,
    echo=False,
    connect_args={"check_same_thread": False},  # required for SQLite
)

SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


class AsyncSessionWrapper:
    """
    Transparent asynchronous wrapper around synchronous SQLAlchemy Session.
    Provides async equivalents of execute, get, commit, rollback, flush, refresh, and close.
    """

    def __init__(self, sync_session: Session) -> None:
        self._s = sync_session

    async def execute(self, statement: Any, *args, **kwargs) -> Any:
        return self._s.execute(statement, *args, **kwargs)

    async def get(self, entity: Any, ident: Any, *args, **kwargs) -> Any:
        return self._s.get(entity, ident, *args, **kwargs)

    async def commit(self) -> None:
        self._s.commit()

    async def rollback(self) -> None:
        self._s.rollback()

    async def flush(self) -> None:
        self._s.flush()

    async def refresh(self, instance: Any, *args, **kwargs) -> None:
        self._s.refresh(instance, *args, **kwargs)

    async def delete(self, instance: Any) -> None:
        self._s.delete(instance)

    async def close(self) -> None:
        self._s.close()

    def add(self, instance: Any) -> None:
        self._s.add(instance)

    def add_all(self, instances: list) -> None:
        self._s.add_all(instances)

    async def __aenter__(self) -> AsyncSessionWrapper:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()
        await self.close()


# Type alias for router dependencies
AsyncSession = AsyncSessionWrapper


@asynccontextmanager
async def async_session_factory() -> AsyncGenerator[AsyncSessionWrapper, None]:
    """Factory creating wrapped async sessions for tasks and websocket handlers."""
    session = SessionLocal()
    wrapper = AsyncSessionWrapper(session)
    try:
        yield wrapper
        await wrapper.commit()
    except Exception:
        await wrapper.rollback()
        raise
    finally:
        await wrapper.close()


async def init_db() -> None:
    """Create all tables that do not yet exist."""
    import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


async def get_db() -> AsyncGenerator[AsyncSessionWrapper, None]:
    """FastAPI dependency — yields an async DB session and closes it after use."""
    async with async_session_factory() as session:
        yield session
