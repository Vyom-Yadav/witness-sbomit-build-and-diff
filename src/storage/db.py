from __future__ import annotations

from pathlib import Path
from logging import getLogger

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from src.config import settings
from src.storage.models import Base


logger = getLogger(__name__)


def _get_db_url() -> str:
    db_path = Path(settings.db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


engine = create_engine(
    _get_db_url(),
    echo=False,
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

_initialized = False


def init_db() -> None:
    global _initialized
    if not _initialized:
        Base.metadata.create_all(bind=engine)
        _initialized = True
        logger.info("Database initialized at %s", settings.db_path)


def get_session() -> Session:
    return SessionLocal()
