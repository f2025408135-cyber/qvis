"""
Database factory.
Returns the correct database implementation based on DATABASE_URL.
"""
from backend.config import Settings
from backend.storage.base import AbstractDatabase

def create_database(settings: Settings) -> AbstractDatabase:
    """
    Factory function: return SQLite or PostgreSQL based on DATABASE_URL.

    SQLite: DATABASE_URL=sqlite:///./data/qvis.db (default)
    PostgreSQL: DATABASE_URL=postgresql://user:pass@host/dbname
    """
    url = settings.database_url.get_secret_value()

    if url.startswith(("postgresql://", "postgres://", "postgresql+asyncpg://")):
        from backend.storage.postgres_db import PostgreSQLDatabase
        return PostgreSQLDatabase(
            database_url=url,
            pool_size=settings.db_pool_size,
        )
    else:
        # Default: SQLite
        db_path = url.replace("sqlite:///", "").replace("sqlite+aiosqlite:///", "")
        from backend.storage.sqlite_db import SQLiteDatabase
        return SQLiteDatabase(db_path=db_path)
