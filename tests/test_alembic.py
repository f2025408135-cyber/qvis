"""Comprehensive tests for Alembic migration infrastructure.

Covers:
- SQLAlchemy ORM model definitions (storage/models.py)
- Alembic migration runner (storage/migrations.py)
- Alembic env.py URL resolution
- Settings.database_url configuration
- Integration: init_db() runs Alembic migrations
- Backward compatibility: existing DDL + Alembic coexist
"""

import os
import sys
import tempfile
import pytest

# Ensure project root (qvis/) is on sys.path for all imports.
# tests/ -> qvis/ (parent.parent)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ═══════════════════════════════════════════════════════════════════════
#  1. SQLAlchemy ORM Models
# ═══════════════════════════════════════════════════════════════════════

class TestORMModels:
    """Verify that the declarative models match the existing DDL."""

    def test_base_is_declarative(self):
        """Base should be a SQLAlchemy DeclarativeBase."""
        from backend.storage.models import Base
        from sqlalchemy.orm import DeclarativeBase
        assert issubclass(Base, DeclarativeBase)

    def test_threat_events_table_name(self):
        """ThreatEventModel should map to 'threat_events' table."""
        from backend.storage.models import ThreatEventModel
        assert ThreatEventModel.__tablename__ == "threat_events"

    def test_threat_events_columns(self):
        """All threat_events columns should be defined with correct types."""
        from backend.storage.models import ThreatEventModel
        import sqlalchemy as sa

        cols = {c.name: c for c in ThreatEventModel.__table__.columns}

        expected_cols = [
            "id", "technique_id", "severity", "platform", "backend_id",
            "title", "description", "evidence", "detected_at",
            "visual_effect", "visual_intensity", "remediation", "resolved_at",
        ]
        for col_name in expected_cols:
            assert col_name in cols, f"Missing column: {col_name}"

        assert cols["id"].primary_key is True
        assert cols["id"].nullable is False
        assert cols["technique_id"].nullable is False
        assert cols["severity"].nullable is False
        assert cols["platform"].nullable is False
        assert cols["backend_id"].nullable is True
        assert cols["resolved_at"].nullable is True
        assert isinstance(cols["id"].type, sa.Text)
        assert isinstance(cols["visual_intensity"].type, sa.Float)

    def test_correlation_events_table_name(self):
        """CorrelationEventModel should map to 'correlation_events' table."""
        from backend.storage.models import CorrelationEventModel
        assert CorrelationEventModel.__tablename__ == "correlation_events"

    def test_correlation_events_columns(self):
        """All correlation_events columns should be defined correctly."""
        from backend.storage.models import CorrelationEventModel
        import sqlalchemy as sa

        cols = {c.name: c for c in CorrelationEventModel.__table__.columns}

        expected_cols = [
            "id", "pattern_name", "techniques", "backends",
            "detected_at", "severity",
        ]
        for col_name in expected_cols:
            assert col_name in cols, f"Missing column: {col_name}"

        assert cols["id"].primary_key is True
        assert cols["id"].nullable is False
        assert cols["pattern_name"].nullable is False

    def test_models_exported(self):
        """Both models and Base should be in __all__."""
        from backend.storage import models
        assert "Base" in models.__all__
        assert "ThreatEventModel" in models.__all__
        assert "CorrelationEventModel" in models.__all__


# ═══════════════════════════════════════════════════════════════════════
#  2. Alembic Configuration
# ═══════════════════════════════════════════════════════════════════════

class TestAlembicConfig:
    """Verify alembic.ini and env.py are correctly configured."""

    def test_alembic_ini_exists(self):
        """alembic.ini should exist at project root."""
        assert os.path.isfile(os.path.join(_PROJECT_ROOT, "alembic.ini"))

    def test_alembic_dir_exists(self):
        """alembic/ directory should exist with versions/ subdirectory."""
        assert os.path.isdir(os.path.join(_PROJECT_ROOT, "alembic"))
        assert os.path.isdir(os.path.join(_PROJECT_ROOT, "alembic", "versions"))

    def test_env_py_exists(self):
        """alembic/env.py should exist."""
        assert os.path.isfile(os.path.join(_PROJECT_ROOT, "alembic", "env.py"))

    def test_initial_migration_exists(self):
        """The initial migration file should exist."""
        versions_dir = os.path.join(_PROJECT_ROOT, "alembic", "versions")
        files = [f for f in os.listdir(versions_dir) if f.endswith(".py")]
        assert len(files) >= 2, "Need at least __init__.py and one migration"
        initial = [f for f in files if "initial" in f]
        assert len(initial) >= 1, "Initial migration file not found"

    def test_alembic_config_reads_database_url(self):
        """alembic.ini should have a default SQLite URL."""
        from alembic.config import Config
        cfg = Config(os.path.join(_PROJECT_ROOT, "alembic.ini"))
        default_url = cfg.get_main_option("sqlalchemy.url")
        assert "sqlite" in default_url.lower()

    def test_alembic_file_template_includes_timestamp(self):
        """Migration filenames should include timestamps for ordering."""
        from alembic.config import Config
        cfg = Config(os.path.join(_PROJECT_ROOT, "alembic.ini"))
        template = cfg.get_main_option("file_template")
        assert "year" in template
        assert "month" in template
        assert "rev" in template


# ═══════════════════════════════════════════════════════════════════════
#  3. Migration Runner
# ═══════════════════════════════════════════════════════════════════════

class TestMigrationRunner:
    """Test the migration runner module."""

    def test_run_migrations_importable(self):
        """run_migrations should be importable."""
        from backend.storage.migrations import run_migrations
        assert callable(run_migrations)

    def test_get_current_revision_importable(self):
        """get_current_revision should be importable."""
        from backend.storage.migrations import get_current_revision
        assert callable(get_current_revision)

    def test_run_migrations_on_fresh_db(self):
        """Running migrations on a fresh SQLite DB should create tables."""
        from backend.storage.migrations import run_migrations

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_migrate.db")
            url = f"sqlite+aiosqlite:///{db_path}"

            run_migrations(database_url=url)

            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()

            assert "threat_events" in tables
            assert "correlation_events" in tables
            assert "alembic_version" in tables

    def test_run_migrations_is_idempotent(self):
        """Running migrations twice should not fail."""
        from backend.storage.migrations import run_migrations

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_idempotent.db")
            url = f"sqlite+aiosqlite:///{db_path}"

            run_migrations(database_url=url)
            run_migrations(database_url=url)

            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.execute("SELECT version_num FROM alembic_version")
            versions = [row[0] for row in cursor.fetchall()]
            conn.close()

            assert len(versions) == 1

    def test_get_current_revision_on_migrated_db(self):
        """get_current_revision should return the revision after migration."""
        from backend.storage.migrations import run_migrations, get_current_revision

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_revision.db")
            url = f"sqlite+aiosqlite:///{db_path}"

            run_migrations(database_url=url)
            revision = get_current_revision(database_url=url)

            assert revision is not None
            assert len(revision) > 0

    def test_get_current_revision_on_empty_db(self):
        """get_current_revision should return None for an unmigrated DB."""
        from backend.storage.migrations import get_current_revision

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_empty.db")
            url = f"sqlite+aiosqlite:///{db_path}"

            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.close()

            revision = get_current_revision(database_url=url)
            assert revision is None


# ═══════════════════════════════════════════════════════════════════════
#  4. Settings.database_url
# ═══════════════════════════════════════════════════════════════════════

class TestDatabaseUrlSetting:
    """Verify the new database_url setting in Settings."""

    def test_default_is_sqlite(self):
        """Default database_url should be SQLite."""
        # Clear any DATABASE_URL env var that might interfere
        saved = os.environ.pop("DATABASE_URL", None)
        try:
            from importlib import reload
            import backend.config
            reload(backend.config)
            s = backend.config.settings
            assert "sqlite" in s.database_url
        finally:
            if saved is not None:
                os.environ["DATABASE_URL"] = saved
            from importlib import reload
            import backend.config
            reload(backend.config)

    def test_can_be_overridden_by_env(self):
        """DATABASE_URL env var should override the default."""
        os.environ["DATABASE_URL"] = "postgresql+asyncpg://user:pass@host:5432/qvis"
        try:
            from importlib import reload
            import backend.config
            reload(backend.config)
            s = backend.config.Settings(_env_file=None)
            assert "postgresql" in s.database_url
        finally:
            os.environ.pop("DATABASE_URL", None)
            from importlib import reload
            import backend.config
            reload(backend.config)

    def test_settings_repr_still_works(self):
        """Settings repr should not break with the new field."""
        from backend.config import Settings
        s = Settings(_env_file=None)
        r = repr(s)
        assert "Settings(" in r


# ═══════════════════════════════════════════════════════════════════════
#  5. URL Translation
# ═══════════════════════════════════════════════════════════════════════

class TestURLTranslation:
    """Verify that async driver URLs are correctly translated to sync."""

    def test_sqlite_async_to_sync(self):
        """sqlite+aiosqlite:// input should work with the migration runner."""
        from backend.storage.migrations import run_migrations

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_url_translate.db")
            url = f"sqlite+aiosqlite:///{db_path}"
            run_migrations(database_url=url)

            import sqlite3
            conn = sqlite3.connect(db_path)
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            conn.close()
            assert "alembic_version" in tables


# ═══════════════════════════════════════════════════════════════════════
#  6. Database Integration (init_db + Alembic)
# ═══════════════════════════════════════════════════════════════════════

class TestInitDbWithAlembic:
    """Verify that init_db() runs Alembic migrations after DDL."""

    @pytest.mark.asyncio
    async def test_init_db_creates_tables_and_alembic_version(self):
        """init_db should create tables AND stamp alembic_version."""
        from backend.storage import database

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_init.db")

            orig_conn = database._connection
            orig_path = database._db_path
            database._connection = None

            try:
                await database.init_db(db_path=db_path)

                import sqlite3
                conn = sqlite3.connect(db_path)
                cursor = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
                tables = [row[0] for row in cursor.fetchall()]
                conn.close()

                assert "threat_events" in tables
                assert "correlation_events" in tables
                assert "alembic_version" in tables

            finally:
                await database.close_db()
                database._connection = orig_conn
                database._db_path = orig_path

    @pytest.mark.asyncio
    async def test_existing_db_still_works(self):
        """An existing database without alembic_version should still work."""
        from backend.storage import database

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_existing.db")

            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.executescript(database._DDL)
            conn.commit()
            conn.close()

            orig_conn = database._connection
            orig_path = database._db_path
            database._connection = None

            try:
                await database.init_db(db_path=db_path)

                await database.save_threat(
                    id="test-001",
                    technique_id="QTT001",
                    severity="high",
                    platform="ibm_quantum",
                    backend_id="ibm_test",
                    title="Test Threat",
                    description="Test",
                    evidence={"test": True},
                    detected_at="2026-04-18T00:00:00Z",
                    visual_effect="pulse",
                    visual_intensity=0.5,
                    remediation=["Fix it"],
                )

                threats = await database.get_threats()
                assert len(threats) == 1
                assert threats[0]["id"] == "test-001"

            finally:
                await database.close_db()
                database._connection = orig_conn
                database._db_path = orig_path


# ═══════════════════════════════════════════════════════════════════════
#  7. Migration Script Content Validation
# ═══════════════════════════════════════════════════════════════════════

class TestMigrationScriptContent:
    """Verify the initial migration script has correct structure."""

    def _get_initial_migration_source(self):
        """Helper: find and read the initial migration file."""
        versions_dir = os.path.join(_PROJECT_ROOT, "alembic", "versions")
        files = [f for f in os.listdir(versions_dir) if f.endswith(".py") and "initial" in f]
        assert len(files) >= 1, "Initial migration file not found"
        filepath = os.path.join(versions_dir, files[0])
        with open(filepath) as f:
            return f.read()

    def test_initial_migration_has_upgrade_downgrade(self):
        source = self._get_initial_migration_source()
        assert "def upgrade()" in source
        assert "def downgrade()" in source

    def test_initial_migration_creates_both_tables(self):
        source = self._get_initial_migration_source()
        assert "threat_events" in source
        assert "correlation_events" in source

    def test_initial_migration_revision_id(self):
        source = self._get_initial_migration_source()
        assert 'revision: str = "0001_initial"' in source
        assert "down_revision" in source

    def test_initial_migration_has_indexes(self):
        source = self._get_initial_migration_source()
        expected_indexes = [
            "idx_threats_detected_at",
            "idx_threats_severity",
            "idx_threats_technique_id",
            "idx_threats_backend_id",
            "idx_threats_resolved_at",
            "idx_corr_detected_at",
        ]
        for idx in expected_indexes:
            assert idx in source, f"Missing index: {idx}"


# ═══════════════════════════════════════════════════════════════════════
#  8. Backward Compatibility
# ═══════════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Ensure existing code paths still work unchanged."""

    def test_db_path_still_exported(self):
        from backend.storage.database import _db_path
        assert isinstance(_db_path, str)
        assert "qvis.db" in _db_path

    def test_get_init_lock_still_exists(self):
        from backend.storage.database import _get_init_lock
        lock1 = _get_init_lock()
        lock2 = _get_init_lock()
        assert lock1 is lock2

    def test_all_crud_functions_importable(self):
        from backend.storage.database import (
            init_db, close_db, _get_connection,
            save_threat, get_threats, get_threat_by_id,
            resolve_threat, get_threat_count,
            save_correlation, get_correlations,
            get_threat_stats,
        )
        assert callable(init_db)
        assert callable(close_db)
        assert callable(save_threat)
        assert callable(get_threats)
        assert callable(save_correlation)

    def test_ddl_has_create_if_not_exists(self):
        from backend.storage.database import _DDL
        assert "CREATE TABLE IF NOT EXISTS threat_events" in _DDL
        assert "CREATE TABLE IF NOT EXISTS correlation_events" in _DDL

    def test_main_imports_unchanged(self):
        from backend.storage.database import init_db, close_db
        assert callable(init_db)
        assert callable(close_db)


# ═══════════════════════════════════════════════════════════════════════
#  9. Docker Compose Configuration
# ═══════════════════════════════════════════════════════════════════════

class TestDockerComposePostgres:
    """Verify docker-compose.yml has PostgreSQL configuration."""

    def test_database_url_env_var(self):
        dc_path = os.path.join(_PROJECT_ROOT, "docker-compose.yml")
        with open(dc_path) as f:
            content = f.read()
        assert "DATABASE_URL" in content

    def test_postgres_service_commented(self):
        dc_path = os.path.join(_PROJECT_ROOT, "docker-compose.yml")
        with open(dc_path) as f:
            content = f.read()
        assert "postgres:" in content
        assert "postgres:16-alpine" in content


# ═══════════════════════════════════════════════════════════════════════
#  10. Requirements
# ═══════════════════════════════════════════════════════════════════════

class TestRequirements:
    """Verify new dependencies are listed in requirements.txt."""

    def _read_requirements(self):
        req_path = os.path.join(_PROJECT_ROOT, "requirements.txt")
        with open(req_path) as f:
            return f.read()

    def test_alembic_in_requirements(self):
        content = self._read_requirements()
        assert "alembic" in content

    def test_sqlalchemy_in_requirements(self):
        content = self._read_requirements()
        assert "sqlalchemy" in content

    def test_asyncpg_commented_in_requirements(self):
        content = self._read_requirements()
        assert "asyncpg" in content
