"""Tests for CI pipeline configuration (CHUNK 06).

Validates:
- ci.yml workflow is syntactically valid YAML
- ci.yml contains all required jobs
- ci.yml references correct paths and services
- .gitignore covers expected patterns
- CODEOWNERS file exists and is well-formed
"""

import os
import yaml
import pytest

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")


def _load_yaml(path: str) -> dict:
    """Load a YAML file from the repo root."""
    full = os.path.join(_REPO_ROOT, path)
    with open(full) as f:
        return yaml.safe_load(f)


# ─── Workflow Structure ──────────────────────────────────────────────────

class TestCIWorkflow:
    """Validate .github/workflows/ci.yml structure."""

    def test_workflow_file_exists(self):
        path = os.path.join(_REPO_ROOT, ".github", "workflows", "ci.yml")
        assert os.path.isfile(path), "ci.yml workflow must exist"

    def test_valid_yaml(self):
        data = _load_yaml(".github/workflows/ci.yml")
        assert isinstance(data, dict)

    def test_has_correct_trigger(self):
        data = _load_yaml(".github/workflows/ci.yml")
        # YAML parses "on" as boolean True — use raw dict access
        raw = yaml.safe_load(open(os.path.join(_REPO_ROOT, ".github", "workflows", "ci.yml")))
        on = raw.get(True, raw.get("on", {}))
        assert "push" in on, "Workflow must trigger on push"
        assert "main" in on["push"]["branches"]
        assert "pull_request" in on, "Workflow must trigger on PRs"
        assert "main" in on["pull_request"]["branches"]

    def test_has_concurrency(self):
        data = _load_yaml(".github/workflows/ci.yml")
        assert "concurrency" in data
        assert data["concurrency"]["cancel-in-progress"] is True

    def test_required_jobs_exist(self):
        data = _load_yaml(".github/workflows/ci.yml")
        jobs = data.get("jobs", {})
        required = ["lint", "test", "build", "security", "merge-gate"]
        for job_name in required:
            assert job_name in jobs, f"Required job '{job_name}' missing"

    def test_lint_job_uses_ruff(self):
        data = _load_yaml(".github/workflows/ci.yml")
        lint = data["jobs"]["lint"]
        steps = lint.get("runs-on", "")
        assert "ubuntu" in steps
        # Find a step that mentions ruff
        step_names = " ".join(str(s) for s in lint.get("steps", []))
        assert "ruff" in step_names

    def test_test_job_matrix(self):
        data = _load_yaml(".github/workflows/ci.yml")
        test = data["jobs"]["test"]
        matrix = test.get("strategy", {}).get("matrix", {})
        assert "python-version" in matrix
        assert "3.11" in matrix["python-version"]
        assert "3.12" in matrix["python-version"]

    def test_test_job_postgres_service(self):
        data = _load_yaml(".github/workflows/ci.yml")
        test = data["jobs"]["test"]
        services = test.get("services", {})
        assert "postgres" in services, "PostgreSQL service container required for migration tests"

    def test_build_job_docker(self):
        data = _load_yaml(".github/workflows/ci.yml")
        build = data["jobs"]["build"]
        step_str = " ".join(str(s) for s in build.get("steps", []))
        assert "docker/build-push-action" in step_str
        assert "smoke" in step_str.lower() or "health" in step_str.lower()

    def test_security_job_bandit(self):
        data = _load_yaml(".github/workflows/ci.yml")
        security = data["jobs"]["security"]
        step_str = " ".join(str(s) for s in security.get("steps", []))
        assert "bandit" in step_str

    def test_merge_gate_depends_on_all(self):
        data = _load_yaml(".github/workflows/ci.yml")
        gate = data["jobs"]["merge-gate"]
        needs = gate.get("needs", [])
        required = ["lint", "test", "build", "security"]
        for req in required:
            assert req in needs, f"merge-gate must depend on '{req}'"

    def test_env_vars_set(self):
        data = _load_yaml(".github/workflows/ci.yml")
        env = data.get("env", {})
        assert env.get("DEMO_MODE") == "true"
        assert env.get("USE_MOCK") == "true"

    def test_workflow_yml_does_not_parse_on_as_bool(self):
        """Ensure 'on' key is not parsed as Python True.

        GitHub Actions uses 'on' as a special key but PyYAML interprets
        it as boolean True. We validate the raw file content instead.
        """
        raw_content = open(os.path.join(_REPO_ROOT, ".github", "workflows", "ci.yml")).read()
        assert "on:" in raw_content
        assert "push:" in raw_content
        assert "pull_request:" in raw_content


# ─── .gitignore ──────────────────────────────────────────────────────────

class TestGitignore:
    """Validate .gitignore covers expected patterns."""

    def test_gitignore_exists(self):
        assert os.path.isfile(os.path.join(_REPO_ROOT, ".gitignore"))

    def test_covers_pycache(self):
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert "__pycache__" in content

    def test_covers_env_files(self):
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert ".env" in content

    def test_covers_coverage(self):
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert "coverage" in content or ".coverage" in content

    def test_covers_database(self):
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert ".db" in content

    def test_covers_ide_files(self):
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert ".vscode" in content or ".idea" in content

    def test_no_markdown_fences(self):
        """The .gitignore should not contain markdown code fences."""
        content = open(os.path.join(_REPO_ROOT, ".gitignore")).read()
        assert "```" not in content, ".gitignore must not contain markdown fences"


# ─── CODEOWNERS ─────────────────────────────────────────────────────────

class TestCodeowners:
    """Validate .github/CODEOWNERS structure."""

    def test_codeowners_exists(self):
        assert os.path.isfile(os.path.join(_REPO_ROOT, ".github", "CODEOWNERS"))

    def test_codeowners_not_empty(self):
        content = open(os.path.join(_REPO_ROOT, ".github", "CODEOWNERS")).read()
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        assert len(lines) > 0, "CODEOWNERS must have at least one entry"

    def test_codeowners_covers_backend(self):
        content = open(os.path.join(_REPO_ROOT, ".github", "CODEOWNERS")).read()
        assert "/backend/" in content

    def test_codeowners_covers_frontend(self):
        content = open(os.path.join(_REPO_ROOT, ".github", "CODEOWNERS")).read()
        assert "/frontend/" in content

    def test_codeowners_covers_ci(self):
        content = open(os.path.join(_REPO_ROOT, ".github", "CODEOWNERS")).read()
        assert ".github" in content or "/.github/" in content
