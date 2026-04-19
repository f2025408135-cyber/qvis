# Contributing to QVis

Welcome to QVis! As a threat intelligence visualization platform, community contributions expanding the Q-ATT&CK framework and its detection rules are highly encouraged.

## 1. Quick Start

To set up a local development environment, follow these steps:

```bash
git clone https://github.com/[username]/qvis
cd qvis
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pytest tests/ -v
uvicorn backend.main:app --reload
```

## 2. How to Add a New Detection Rule

To add a new Q-ATT&CK technique detection rule, implement a pure Python function in `backend/threat_engine/rules.py`.

Here is a complete example of adding **QTT011**:

```python
# In backend/threat_engine/rules.py

def rule_011_example_technique(
    snapshot: Union[SimulationSnapshot, dict],
    cfg: ThresholdConfig | None = None,
) -> list[ThreatEvent]:
    """
    Detect [TECHNIQUE NAME].

    Theoretical basis: [cite paper or describe attack vector]
    MITRE ATT&CK mapping: [TA-XXXX]

    Args:
        snapshot: Current simulation state from the collector.
        cfg: Optional threshold configuration override.

    Returns:
        List of ThreatEvents. Empty list if no threat detected.
    """
    _cfg = cfg or _get_default_config()
    events = []

    backends = (
        snapshot.get("backends", [])
        if isinstance(snapshot, dict)
        else snapshot.backends
    )

    for backend in backends:
        # Your detection logic here
        if some_condition_exceeded(_cfg.your_new_threshold):
            events.append(ThreatEvent(
                technique_id="QTT011",
                technique_name="Your Technique Name",
                severity=Severity.medium,
                platform=backend.platform,
                backend_id=backend.id,
                title="Example Threat Title",
                description="Describe the anomaly detected.",
                detected_at=datetime.now(timezone.utc),
                visual_effect="vortex",
                visual_intensity=0.5,
                remediation=["Review technique vector."],
                evidence={
                    "rule_name": "rule_011_example_technique",  # G6 required
                    "threshold_used": _cfg.your_new_threshold,  # G6 required
                    # ... additional evidence fields ...
                },
            ))

    return events
```

## 3. Quality Gates Checklist

- **G5 (Threshold Config):** All thresholds must be loaded via `_cfg = cfg or _get_default_config()` and never hardcoded.
- **G6 (Evidence Schema):** The returned `evidence` dict must contain `"rule_name"` and `"threshold_used"`.
- **G7 (Pure Function):** The detection rule must be entirely pure without any database or I/O side effects.

## 4. Test Requirements

When adding a new rule, you must write at least 8 tests for it in `tests/test_rules.py`:

- **positive_case:** Rule fires correctly when the threshold is exceeded.
- **negative_case_below:** Rule DOES NOT fire when the value is below the threshold.
- **negative_case_empty:** Rule handles empty backends or missing data gracefully without throwing exceptions.
- **threshold_override:** Ensures the rule correctly uses a custom threshold via `ThresholdConfig` override.
- **evidence_schema:** Validates the `evidence` dictionary outputs the `"rule_name"` and `"threshold_used"` keys.
- **technique_id_valid:** Confirms the returned `technique_id` conforms to the `QTT001-QTT020` naming standard.
- **enabled_rules_respected:** Ensures the rule correctly skips when it is disabled inside `enabled_rules`.
- **dict_mode:** Verifies the rule works transparently whether the input is a raw `dict` or a structured Pydantic model (`SimulationSnapshot`).

## 5. Adding to Q-ATT&CK Taxonomy

After completing the tests, update the documentation:

1. Update the Q-ATT&CK technique table in `docs/quantum-threat-taxonomy.md` with your new row.
2. Update the summarized technique table inside the project's root `README.md`.
