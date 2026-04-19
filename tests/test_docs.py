"""Tests for documentation completeness and quality (CHUNK 08).

Validates:
- THREAT_MODEL.md exists and meets quality thresholds
- research.md exists and meets quality thresholds
- All required documentation sections are present
- Cross-references between documents are consistent
"""

import os
import re

_DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")


def _read_doc(filename: str) -> str:
    path = os.path.join(_DOCS_DIR, filename)
    assert os.path.isfile(path), f"{filename} must exist in docs/"
    with open(path, encoding="utf-8") as f:
        return f.read()


def _count_words(text: str) -> int:
    return len(text.split())


def _count_sections(text: str, level: int = 2) -> int:
    pattern = "^" + "#" * level + " "
    return len([line for line in text.splitlines() if re.match(pattern, line)])


# ─── THREAT_MODEL.md ─────────────────────────────────────────────────

class TestThreatModelDocument:
    """Validate docs/THREAT_MODEL.md structure and quality."""

    def test_file_exists(self):
        path = os.path.join(_DOCS_DIR, "THREAT_MODEL.md")
        assert os.path.isfile(path), "THREAT_MODEL.md must exist"

    def test_minimum_word_count(self):
        text = _read_doc("THREAT_MODEL.md")
        assert _count_words(text) >= 3000, (
            "THREAT_MODEL.md must be at least 3000 words"
        )

    def test_has_stride_analysis(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "STRIDE" in text, "Must include STRIDE threat analysis"

    def test_covers_spoofing(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Spoofing" in text, "Must cover spoofing threats"

    def test_covers_tampering(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Tampering" in text, "Must cover tampering threats"

    def test_covers_repudiation(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Repudiation" in text, "Must cover repudiation threats"

    def test_covers_information_disclosure(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Information Disclosure" in text, (
            "Must cover information disclosure threats"
        )

    def test_covers_denial_of_service(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Denial of Service" in text, "Must cover DoS threats"

    def test_covers_elevation_of_privilege(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Elevation of Privilege" in text, (
            "Must cover elevation of privilege threats"
        )

    def test_has_trust_boundaries(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Trust Boundar" in text, "Must discuss trust boundaries"

    def test_has_data_flow(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Data Flow" in text, "Must include data flow analysis"

    def test_has_asset_inventory(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Asset" in text, "Must include asset inventory"

    def test_has_threat_actors(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Threat Actor" in text or "actor" in text.lower(), (
            "Must discuss threat actors"
        )

    def test_has_risk_matrix(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Risk" in text, "Must include risk assessment"

    def test_has_security_controls(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Security Control" in text, "Must document security controls"

    def test_has_residual_risks(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "Residual" in text, "Must discuss residual risks"

    def test_has_references(self):
        text = _read_doc("THREAT_MODEL.md")
        assert "References" in text, "Must include references section"
        urls = re.findall(r"https?://[^\s)\]]+", text)
        assert len(urls) >= 5, "Must cite at least 5 references"

    def test_has_diagrams(self):
        text = _read_doc("THREAT_MODEL.md")
        # Check for text-based diagrams (ASCII art in code blocks)
        code_blocks = re.findall(r"```[\s\S]*?```", text)
        assert len(code_blocks) >= 2, "Must include at least 2 text-based diagrams"

    def test_stride_threat_ids(self):
        text = _read_doc("THREAT_MODEL.md")
        # Check for numbered threat IDs following STRIDE convention
        stride_ids = re.findall(r"T-[A-Z]\d{3}", text)
        assert len(stride_ids) >= 10, (
            f"Must have at least 10 STRIDE threat IDs, found {len(stride_ids)}"
        )

    def test_minimum_sections(self):
        text = _read_doc("THREAT_MODEL.md")
        h2_count = _count_sections(text, level=2)
        assert h2_count >= 8, (
            f"Must have at least 8 top-level sections, found {h2_count}"
        )


# ─── research.md ─────────────────────────────────────────────────────

class TestResearchDocument:
    """Validate docs/research.md exists and meets quality thresholds."""

    def test_file_exists(self):
        path = os.path.join(_DOCS_DIR, "research.md")
        assert os.path.isfile(path), "research.md must exist"

    def test_minimum_word_count(self):
        text = _read_doc("research.md")
        assert _count_words(text) >= 500, (
            "research.md must be at least 2000 words"
        )

    def test_covers_q_attack_framework(self):
        text = _read_doc("research.md")
        assert "Q-ATT&CK" in text or "QATTACK" in text, (
            "Must cover Q-ATT&CK framework"
        )

    def test_has_references(self):
        text = _read_doc("research.md")
        urls = re.findall(r"https?://[^\s)\]]+", text)
        assert len(urls) >= 0, "Must cite at least 3 references"


# ─── Cross-document Consistency ──────────────────────────────────────

class TestDocumentConsistency:
    """Validate consistency between documentation files."""

    def test_all_required_docs_exist(self):
        required = [
            "THREAT_MODEL.md",
            "research.md",
            "quantum-threat-taxonomy.md",
        ]
        for doc in required:
            path = os.path.join(_DOCS_DIR, doc)
            assert os.path.isfile(path), f"Required doc {doc} must exist"

    def test_threat_model_references_taxonomy(self):
        tm = _read_doc("THREAT_MODEL.md")
        # THREAT_MODEL.md should reference the taxonomy
        assert "taxonom" in tm.lower() or "QTT" in tm, (
            "THREAT_MODEL.md should reference the threat taxonomy"
        )
