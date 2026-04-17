# QVis — Quantum Threat Intelligence Visualization System

## Complete Architecture Reference

> **Version**: 1.0  
> **Last Updated**: 2026-04-18  
> **Repository**: https://github.com/f2025408135-cyber/qvis

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Project File Structure](#3-project-file-structure)
4. [Data Models](#4-data-models)
5. [Backend Architecture](#5-backend-architecture)
6. [Threat Engine — Detection Rules](#6-threat-engine--detection-rules)
7. [Threat Engine — Analyzer (Orchestration)](#7-threat-engine--analyzer-orchestration)
8. [Threat Engine — Correlation Engine](#8-threat-engine--correlation-engine)
9. [Threat Engine — Baseline Manager](#9-threat-engine--baseline-manager)
10. [Collectors Subsystem](#10-collectors-subsystem)
11. [API Layer](#11-api-layer)
12. [Security Layer](#12-security-layer)
13. [Storage Layer](#13-storage-layer)
14. [Frontend Architecture](#14-frontend-architecture)
15. [WebSocket Protocol](#15-websocket-protocol)
16. [Configuration System](#16-configuration-system)
17. [Simulation Loop (Main Pipeline)](#17-simulation-loop-main-pipeline)
18. [Q-ATT&CK Framework Mapping](#18-q-attack-framework-mapping)
19. [Scenario Playback System](#19-scenario-playback-system)
20. [Threshold Calibration](#20-threshold-calibration)
21. [STIX Export](#21-stix-export)
22. [Deployment & Containerization](#22-deployment--containerization)
23. [Testing Strategy](#23-testing-strategy)
24. [Design Decisions & Quality Gates](#24-design-decisions--quality-gates)

---

## 1. System Overview

QVis (Quantum Threat Intelligence Visualization System) is a real-time threat intelligence platform purpose-built for quantum computing infrastructure. It continuously monitors quantum cloud platforms — IBM Quantum, Amazon Braket, and Azure Quantum — for indicators of compromise and attack patterns specific to quantum computing environments.

The system operates as a closed-loop pipeline:

1. **Collect** — Telemetry is gathered from quantum platforms via platform-specific collectors
2. **Analyze** — A threat engine runs 10 detection rules against the collected data
3. **Correlate** — A correlation engine detects multi-stage attack campaigns
4. **Baseline** — An adaptive baseline manager detects statistical anomalies via z-scores
5. **Persist** — Threat events are stored in SQLite for historical analysis
6. **Broadcast** — Enriched snapshots are pushed to connected clients via WebSocket
7. **Visualize** — A Three.js-powered 3D visualization renders quantum topology and threats

The entire system is designed to run in three modes:
- **Demo Mode** (`DEMO_MODE=true`): Uses mock data from multiple simulated platforms
- **Test Mode** (`USE_MOCK=true`): Deterministic mock data for automated testing
- **Production Mode**: Live connection to real quantum platforms with real API tokens

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          QVis System Architecture                           │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                       │
│   │ IBM Quantum │   │ Amazon      │   │ Azure       │    ← Quantum Platforms │
│   │   (Qiskit)  │   │  Braket     │   │  Quantum    │                       │
│   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘                       │
│          │                 │                 │                               │
│   ┌──────┴─────────────────┴─────────────────┴──────┐                       │
│   │          AggregatorCollector                     │    ← Collectors Layer  │
│   │    ┌───────────┐ ┌──────────┐ ┌──────────────┐  │                       │
│   │    │IBMCollector│ │BraketColl│ │AzureCollector │  │                       │
│   │    └───────────┘ └──────────┘ └──────────────┘  │                       │
│   └─────────────────────┬────────────────────────────┘                       │
│                         │                                                     │
│            ┌────────────┴────────────┐                                      │
│            │  SimulationSnapshot     │    ← Unified Data Model              │
│            └────────────┬────────────┘                                      │
│                         │                                                     │
│   ┌─────────────────────┴────────────────────────────┐                      │
│   │              ThreatAnalyzer                       │    ← Analysis Engine  │
│   │  ┌──────────────────────────────────────────────┐│                      │
│   │  │  RULE_001 │ RULE_002 │ ... │ RULE_010        ││    ← 10 Detection Rules│
│   │  └──────────────────────────────────────────────┘│                      │
│   │  ┌──────────────┐  ┌──────────────────────┐      │                      │
│   │  │ ThreatCorrelator │  │ BaselineManager    │      │    ← Correlation &   │
│   │  └──────────────┘  └──────────────────────┘      │       Anomaly Det.    │
│   └─────────────────────┬────────────────────────────┘                      │
│                         │                                                     │
│          ┌──────────────┼──────────────┐                                     │
│          │              │              │                                      │
│   ┌──────┴──────┐ ┌────┴────┐ ┌───────┴───────┐                           │
│   │   SQLite     │ │WebSocket│ │  REST API      │    ← Output Layer        │
│   │  (persist)   │ │(broadcast│ │  /api/*        │                           │
│   │              │ │ /ws/)    │ │  /health       │                           │
│   └──────┬──────┘ └────┬────┘ └───────┬───────┘                           │
│          │              │              │                                      │
│   ┌──────┴──────────────┴──────────────┴──────┐                             │
│   │              FastAPI Application            │    ← Application Server   │
│   │   Middleware: CORS │ Rate Limit │ Security  │                           │
│   │   Headers │ Request ID │ Auth (optional)    │                           │
│   └──────────────────────┬─────────────────────┘                             │
│                          │                                                    │
│   ┌──────────────────────┴─────────────────────┐                             │
│   │              Frontend (Vanilla JS)          │    ← Visualization Layer   │
│   │   Three.js 3D Engine │ WebSocket Client     │                           │
│   │   ParticleSystem │ Backend │ Entanglement   │                           │
│   │   HUD │ ThreatPanel │ Legend │ Timeline     │                           │
│   │   Canvas2D Fallback │ Audio Engine         │                           │
│   └────────────────────────────────────────────┘                             │
│                                                                          │
│   ┌────────────────────────────────────────────┐                           │
│   │         GitHub Token Scanner                 │    ← External Intel     │
│   │     (periodic GitHub Code Search API)       │                           │
│   └────────────────────────────────────────────┘                           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Project File Structure

```
qvis/
├── backend/
│   ├── __init__.py
│   ├── main.py                          # FastAPI app, simulation loop, lifespan
│   ├── config.py                        # Settings (pydantic-settings)
│   │
│   ├── threat_engine/
│   │   ├── __init__.py
│   │   ├── models.py                     # Pydantic models (Severity, Platform, etc.)
│   │   ├── rules.py                      # 10 detection rules + ThresholdConfig
│   │   ├── analyzer.py                   # ThreatAnalyzer orchestration
│   │   ├── correlator.py                 # ThreatCorrelator (campaign detection)
│   │   └── baseline.py                   # MetricBaseline + BaselineManager
│   │
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py                       # BaseCollector ABC
│   │   ├── mock.py                       # MockCollector (test/demo)
│   │   ├── ibm.py                        # IBMQuantumCollector (live)
│   │   ├── braket.py                     # BraketCollector (live/fallback)
│   │   ├── azure_quantum.py              # AzureQuantumCollector (live/fallback)
│   │   ├── aggregator.py                 # AggregatorCollector (multi-platform merge)
│   │   ├── github_scanner.py             # GitHubTokenScanner
│   │   ├── scenario.py                   # ScenarioCollector (playback)
│   │   └── calibrator.py                 # ThresholdCalibrator
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── auth.py                       # API key authentication
│   │   ├── websocket.py                  # ConnectionManager (WebSocket handling)
│   │   ├── security_headers.py           # SecurityHeadersMiddleware (CSP, HSTS)
│   │   ├── ratelimit.py                  # RateLimitMiddleware (sliding window)
│   │   └── export.py                     # STIX 2.1 export
│   │
│   └── storage/
│       ├── __init__.py
│       └── database.py                   # SQLite persistence (aiosqlite, WAL mode)
│
├── frontend/
│   ├── index.html                        # SPA entry point
│   ├── css/
│   │   └── main.css                      # All styles
│   └── js/
│       ├── main.js                       # Bootstrap, Three.js init, render loop
│       ├── state.js                      # Application state (appState singleton)
│       ├── utils.js                      # Utility functions
│       ├── core/
│       │   ├── FallbackManager.js        # Capability detection, error handling
│       │   ├── AudioEngine.js            # Web Audio API alert sounds
│       │   ├── PerformanceMonitor.js     # FPS counter, render stats
│       │   └── ToastManager.js           # Toast notification system
│       ├── data/
│       │   ├── WSClient.js               # WebSocket client with reconnect
│       │   └── StateMapper.js            # Snapshot → Three.js scene mapping
│       ├── simulation/
│       │   ├── Backend.js                # 3D backend node (icosahedron + rings)
│       │   ├── ParticleSystem.js         # Particle effects (leak, drain, etc.)
│       │   ├── Entanglement.js           # Entanglement pair rendering
│       │   └── ThreatVisuals.js          # Threat visual effects manager
│       ├── ui/
│       │   ├── HUD.js                    # Heads-up display (top bar)
│       │   ├── ThreatPanel.js            # Threat detail side panel
│       │   ├── Legend.js                  # Visualization legend
│       │   ├── Timeline.js               # Event timeline
│       │   └── Controls.js               # OrbitControls wrapper
│       └── renderers/
│           └── Canvas2DFallback.js       # 2D fallback for no-WebGL browsers
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                       # Shared fixtures (autouse config isolation)
│   ├── test_rules.py                     # Detection rule tests
│   ├── test_baseline_manager.py          # Baseline manager tests
│   ├── test_correlator.py                # Correlator tests
│   ├── test_analyzer.py                  # Not used — see test_threat_engine.py
│   ├── test_threat_engine.py             # Full threat engine integration tests
│   ├── test_collectors.py                # Collector tests
│   ├── test_github_scanner.py            # GitHub scanner tests
│   ├── test_api.py                       # API endpoint tests
│   ├── test_e2e.py                       # End-to-end tests
│   ├── test_multiplatform.py             # Multi-platform collector tests
│   ├── test_simulation_state.py          # Simulation state management tests
│   ├── test_defcon_hardening.py          # DEF CON security hardening tests
│   ├── test_fallbacks.py                 # Frontend fallback tests
│   ├── test_scenario.py                  # Scenario playback tests
│   ├── test_priority_fixes.py            # Priority fix regression tests
│   ├── test_integration_fixes.py         # Integration fix tests
│   ├── test_regression_all_fixes.py      # Full regression test suite
│   ├── test_phase1.py                    # Phase 1 acceptance tests
│   └── test_phase2.py                    # Phase 2 acceptance tests
│
├── docs/
│   ├── QVIS_ARCHITECTURE.md              # This document
│   ├── quantum-threat-taxonomy.md        # Q-ATT&CK technique documentation
│   └── defcon-demo-script.md             # DEF CON demonstration script
│
├── data/                                 # Runtime data (SQLite DB, gitignored)
│   ├── qvis.db                           # SQLite database
│   ├── qvis.db-wal                       # WAL journal
│   └── qvis.db-shm                       # WAL shared memory
│
├── scripts/
│   └── record_demo.py                    # Demo recording utility
│
├── Dockerfile                            # Multi-stage Docker build
├── docker-compose.yml                    # Production Docker Compose
├── requirements.txt                      # Python dependencies
├── pyproject.toml                        # Ruff, mypy, pytest config
├── pytest.ini                            # Pytest settings
├── LICENSE                               # MIT License
└── README.md                             # Project documentation
```

---

## 4. Data Models

All data models are defined in `backend/threat_engine/models.py` using Pydantic v2 `BaseModel`.

### 4.1 Severity Enum

```python
class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
```

Severity levels are ordered for sorting: `critical > high > medium > low > info`. The `ThreatAnalyzer._severity_rank()` method maps these to integer ranks (0–4) for sort operations.

### 4.2 Platform Enum

```python
class Platform(str, Enum):
    ibm_quantum = "ibm_quantum"
    amazon_braket = "amazon_braket"
    azure_quantum = "azure_quantum"
```

### 4.3 QubitCalibration

Represents per-qubit calibration metrics from a quantum backend:

| Field | Type | Description |
|-------|------|-------------|
| `qubit_id` | `int` | Logical qubit index |
| `t1_us` | `float` | T1 relaxation time in microseconds |
| `t2_us` | `float` | T2 dephasing time in microseconds |
| `readout_error` | `float` | Readout assignment error probability (0.0–1.0) |
| `gate_error_cx` | `Optional[float]` | CNOT gate error rate (0.0–1.0) |

### 4.4 BackendNode

Represents a quantum computing backend (physical QPU or simulator):

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique backend identifier (e.g., `ibm_sherbrooke`) |
| `name` | `str` | Display name |
| `platform` | `Platform` | Cloud platform enum |
| `num_qubits` | `int` | Number of qubits |
| `is_simulator` | `bool` | Whether this is a simulator (not real hardware) |
| `operational` | `bool` | Whether the backend is currently accepting jobs |
| `calibration` | `List[QubitCalibration]` | Per-qubit calibration data |
| `api_surface_score` | `float` | 0.0–1.0 score indicating attack surface exposure |
| `threat_level` | `Severity` | Current overall threat level for this backend |
| `position_hint` | `Optional[Tuple[float,float,float]]` | Optional 3D position for visualization |

### 4.5 ThreatEvent

The central data structure representing a detected threat:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | UUID4 unique identifier |
| `technique_id` | `str` | Q-ATT&CK technique ID (e.g., `QTT003`) |
| `technique_name` | `str` | Human-readable technique name |
| `severity` | `Severity` | Threat severity level |
| `platform` | `Platform` | Affected platform |
| `backend_id` | `Optional[str]` | Affected backend (can be `None` for platform-wide threats) |
| `title` | `str` | Short title for UI display |
| `description` | `str` | Detailed description of the threat |
| `evidence` | `dict` | Structured evidence dictionary (must contain `rule_name` and `threshold_used` per quality gate G6) |
| `detected_at` | `datetime` | UTC timestamp of detection |
| `visual_effect` | `str` | Name of the visual effect to render |
| `visual_intensity` | `float` | 0.0–1.0 intensity for the visual effect |
| `remediation` | `List[str]` | Recommended remediation steps |

### 4.6 SimulationSnapshot

The top-level data structure that flows through the entire pipeline:

| Field | Type | Description |
|-------|------|-------------|
| `snapshot_id` | `str` | UUID4 for this specific snapshot |
| `generated_at` | `datetime` | When the snapshot was generated |
| `backends` | `List[BackendNode]` | All tracked quantum backends |
| `threats` | `List[ThreatEvent]` | Active detected threats |
| `entanglement_pairs` | `List[Tuple[str, str]]` | Pairs of backend IDs connected visually |
| `total_qubits` | `int` | Sum of all backend qubit counts |
| `total_threats` | `int` | Count of active threats |
| `threats_by_severity` | `Dict[str, int]` | Count per severity level |
| `platform_health` | `Dict[str, float]` | Health score per platform (0.0–1.0) |

The `SimulationSnapshot` model uses `model_config = {"extra": "allow"}` so that the collector can inject additional fields (like `job_history`, `calibration_request_count`, `collection_metadata`) that the rules access via dict mode but aren't part of the strict Pydantic schema.

---

## 5. Backend Architecture

### 5.1 Application Entry Point (`backend/main.py`)

The backend is a FastAPI application with the following lifecycle:

#### Startup Sequence

1. **Logging Configuration** — `_configure_logging()` sets up structlog based on `settings.log_format` (console for dev, JSON for production)
2. **Settings Loading** — `settings = Settings()` loads from `.env` via pydantic-settings
3. **Threshold Config** — `load_threshold_config_from_file()` checks for `calibration_results.json` and installs calibrated thresholds via `set_threshold_config()`
4. **Collector Selection** — Based on environment variables, one of:
   - `MockCollector` — if `USE_MOCK=true` or `PYTEST_CURRENT_TEST` is set
   - `AggregatorCollector([MockCollector, BraketCollector, AzureQuantumCollector])` — if `DEMO_MODE=true`
   - `IBMQuantumCollector` (optionally aggregated with Braket/Azure) — if `IBM_QUANTUM_TOKEN` is set
5. **GitHub Scanner** — Optional `GitHubTokenScanner` if `GITHUB_TOKEN` is set
6. **FastAPI App Creation** — `app = FastAPI(title="QVis API", lifespan=lifespan)`

#### Middleware Stack (execution order)

The middleware is applied in this specific order (first = outermost):

1. **RequestIDMiddleware** — Generates unique `X-Request-ID` for trace correlation
2. **CORSMiddleware** — Cross-origin resource sharing (configurable via `CORS_ORIGINS`)
3. **RateLimitMiddleware** — Sliding-window rate limiting on `/api/*` routes
4. **SecurityHeadersMiddleware** — CSP, HSTS, X-Content-Type-Options, etc.

#### Lifespan Management

The `lifespan()` async context manager handles:

- **Startup**: Initializes SQLite database, runs initial collection + analysis, seeds active threats, launches `simulation_loop()` as background task
- **Shutdown**: Cancels simulation loop, closes database connection

### 5.2 Configuration (`backend/config.py`)

Uses `pydantic_settings.BaseSettings` with `.env` file support. All secrets use `SecretStr` to prevent accidental logging or serialization.

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `demo_mode` | `bool` | `True` | Use mock collectors |
| `update_interval_seconds` | `int` | `30` | Simulation loop interval |
| `ibm_quantum_token` | `SecretStr` | `""` | IBM Quantum API token |
| `aws_access_key_id` | `SecretStr` | `""` | AWS access key |
| `aws_secret_access_key` | `SecretStr` | `""` | AWS secret key |
| `aws_default_region` | `str` | `"us-east-1"` | AWS region |
| `azure_quantum_subscription_id` | `SecretStr` | `""` | Azure subscription |
| `auth_enabled` | `bool` | `False` | Enable API key auth |
| `api_key` | `SecretStr` | `""` | Shared API secret |
| `rate_limit` | `str` | `"60/60"` | Max requests / window seconds |
| `log_level` | `str` | `"INFO"` | Logging level |
| `log_format` | `str` | `"console"` | `console` or `json` |
| `github_token` | `SecretStr` | `""` | GitHub PAT for token scanning |
| `slack_webhook_url` | `SecretStr` | `""` | Slack alerting |
| `discord_webhook_url` | `SecretStr` | `""` | Discord alerting |
| `webhook_url` | `SecretStr` | `""` | Generic webhook |

---

## 6. Threat Engine — Detection Rules

### 6.1 Architecture

All detection rules live in `backend/threat_engine/rules.py`. They follow a strict **pure function design**:

```python
def RULE_NNN_name(data: Dict[str, Any]) -> List[ThreatEvent]:
```

Every rule:
- Accepts a raw dictionary (the snapshot's `model_dump()`)
- Returns a list of `ThreatEvent` objects (empty if no threat detected)
- Has **no side effects** — no logging, no network calls, no database writes
- Uses `_cfg('field_name', default)` to access configurable thresholds

### 6.2 Threshold Configuration System

The `ThresholdConfig` dataclass centralizes all configurable detection thresholds:

```python
@dataclass
class ThresholdConfig:
    rule_002_calibration_harvest_ratio: Optional[float] = None
    rule_003_identity_gate_ratio: Optional[float] = None
    rule_003_max_circuit_gates: Optional[int] = None
    rule_004_max_failed_attempts: Optional[int] = None
    rule_005_max_depth_ratio: Optional[float] = None
    rule_006_max_sequential_404: Optional[int] = None
    rule_007_max_admin_403: Optional[int] = None
    rule_008_t1_baseline_ratio: Optional[float] = None
    rule_009_min_backends_accessed: Optional[int] = None
    rule_010_measure_ratio: Optional[float] = None
    rule_010_min_circuit_gates: Optional[int] = None
    enabled_rules: Optional[set] = None
```

When a field is `None`, the rule uses its hardcoded conservative default. When set, the rule uses the configured value. This allows runtime threshold tuning without code changes.

The `_cfg(attr_name, default)` helper function centralizes the None-guard logic:

```python
def _cfg(attr_name: str, default: Any) -> Any:
    if _threshold_config is None:
        return default
    value = getattr(_threshold_config, attr_name, None)
    return value if value is not None else default
```

### 6.3 Rule Enable/Disable

The `enabled_rules` field in `ThresholdConfig` controls which rules are active:

```python
def get_active_rules() -> list:
    if _threshold_config is not None and _threshold_config.enabled_rules is not None:
        return [r for r in ALL_RULES if r.__name__ in _threshold_config.enabled_rules]
    return list(ALL_RULES)
```

When `enabled_rules` is set, only rules whose `__name__` appears in the set are evaluated. This allows runtime rule management.

### 6.4 Complete Rule Inventory

| Rule Function | Q-ATT&CK ID | Technique Name | Severity | Input Data | Threshold | Visual Effect |
|---------------|-------------|----------------|----------|------------|-----------|---------------|
| `RULE_001_credential_leak_github_search` | QTT007 | Credential Exposure | Critical | `github_search_results` | N/A (any match) | `particle_leak` |
| `RULE_002_calibration_harvest_rate` | QTT002 | Calibration Harvesting | Medium | `api_access_log.calibration_requests_last_hour` / `job_submissions_last_hour` | ratio > 3.0 | `calibration_drain` |
| `RULE_003_timing_oracle_job_pattern` | QTT003 | Timing Oracle | High | `recent_jobs[].gate_histogram` | id_ratio > 0.7 AND total_gates < 20 | `timing_ring` |
| `RULE_004_cross_tenant_id_probing` | QTT004 | Tenant Probing | High | `failed_job_access_attempts` | count > 5 | `color_bleed` |
| `RULE_005_resource_exhaustion_circuit` | QTT008 | Resource Exhaustion | Medium | `recent_jobs[].depth` / `max_allowed_depth` | ratio > 0.85 | `interference` |
| `RULE_006_ip_extraction_idor` | QTT006 | IP Extraction | Critical | `api_error_log.sequential_404_count` | count > 10 | `vortex` |
| `RULE_007_token_scope_violation` | QTT005 | Scope Violation | High | `api_error_log.403_on_admin_count` | count > 3 | `interference` |
| `RULE_008_backend_health_anomaly` | QTT010 | Hardware Degradation | Info | `baseline_calibration` vs `calibration[].t1_us` | current < baseline * 0.6 | `calibration_drain` |
| `RULE_009_concurrent_multi_backend_probing` | QTT001 | Multi-Backend Recon | High | `recent_jobs[].backend_id` | unique backends >= 3 | `color_bleed` |
| `RULE_010_anomalous_circuit_composition` | QTT009 | Anomalous Circuit | Medium | `recent_jobs[].gate_histogram` | measure_ratio > 0.5 AND total_gates > 10 | `interference` |

### 6.5 Evidence Quality Gate (G6)

Every threat event's `evidence` dictionary **must** contain two fields:

```python
evidence={
    "rule_name": "RULE_003_timing_oracle_job_pattern",  # G6 required
    "threshold_used": 0.7,                                # G6 required
    # ... additional contextual evidence
}
```

This ensures auditability — every detection can be traced back to the exact rule and threshold that triggered it.

---

## 7. Threat Engine — Analyzer (Orchestration)

### 7.1 ThreatAnalyzer (`backend/threat_engine/analyzer.py`)

The analyzer is the central orchestration component. It:

1. **Runs all active rules** against the current snapshot
2. **Deduplicates threats** by `(backend_id, technique_id)` key
3. **Manages persistence tracking** — only genuinely new threats are inserted into the database
4. **Resolves disappeared threats** — when a threat key vanishes from active threats, it's marked resolved in the database

#### Key Methods

**`analyze(snapshot)`** — Main analysis method:
- Converts `SimulationSnapshot` to dict via `model_dump()`
- Iterates over `get_active_rules()` calling each rule
- Merges new threats with existing active threats
- Sorts by severity
- Returns enriched `SimulationSnapshot` (or bare list in dict mode)

**`persist_new_threats()`** — Differential persistence:
- Tracks `_persisted_ids` set to avoid redundant INSERTs
- Only saves threats whose ID is not in `_persisted_ids`
- Imports `save_threat` from database module (lazy import to avoid circular deps)

**`resolve_disappeared_threats()`** — Threat resolution:
- Compares current `active_threats` IDs against `_persisted_ids`
- Any persisted ID no longer in active threats gets `resolve_threat()` called
- Removes resolved IDs from `_persisted_ids`

**`reset()`** — Clears all state (used when switching scenarios)

#### Deduplication Logic

The analyzer uses a 5-minute deduplication window per `(backend_id, technique_id)` key. If the same technique fires on the same backend within 5 minutes, the original threat ID is preserved for UI continuity, but the threat's evidence/severity is updated and re-persisted. After the 5-minute window, a new occurrence generates a fresh threat event.

---

## 8. Threat Engine — Correlation Engine

### 8.1 ThreatCorrelator (`backend/threat_engine/correlator.py`)

The correlator detects **multi-stage attack campaigns** by identifying when two or more individual threat techniques co-occur on the same backend within a defined time window.

#### Correlation Patterns

| Pattern Name | Triggering Techniques | Window | Escalated Severity |
|-------------|----------------------|--------|-------------------|
| Coordinated Reconnaissance | QTT003 + QTT002 | 30 min | Critical |
| Pre-Attack Staging | QTT007 + QTT003 | 60 min | Critical |
| Enumeration Campaign | QTT004 + QTT006 | 15 min | Critical |
| Resource Abuse Chain | QTT008 + QTT005 | 30 min | High |

#### How It Works

1. **History Buffer** — Maintains a rolling list of recent threats (configurable `history_hours`, default 2.0 hours, max 500 events)
2. **Pruning** — Old threats beyond the history window are removed each cycle
3. **Pattern Matching** — For each correlation pattern, checks if ALL required techniques are present on the same backend within the time window
4. **Campaign Deduplication** — Uses `_campaign_dedup` set with keys in format `CORR:{backend_id}:{pattern_name}` to prevent the same campaign from firing repeatedly
5. **Dedup Expiry** — Campaign dedup keys expire when none of the underlying technique IDs exist in recent threats anymore

#### Campaign Event Structure

When a correlation pattern matches, a `ThreatEvent` is created with:
- `technique_id`: `CORR:{backend_id}:{pattern_name}` (e.g., `CORR:ibm_sherbrooke:Coordinated Reconnaissance`)
- `severity`: The escalated severity from the pattern definition
- `evidence`: Contains `pattern_name`, `techniques_found`, `backend_id`, `window_minutes`, and `triggering_threats`
- `visual_effect`: `"campaign"`

---

## 9. Threat Engine — Baseline Manager

### 9.1 BaselineManager (`backend/threat_engine/baseline.py`)

The baseline manager provides **adaptive anomaly detection** using Exponential Moving Averages (EMA) and z-scores. This is separate from the static threshold rules and detects gradual statistical drift.

#### MetricBaseline (per-metric tracker)

Each tracked metric (e.g., `ibm_sherbrooke:q0_t1`) has its own `MetricBaseline` instance:

- **EMA (Exponential Moving Average)**: `alpha=0.1` smoothing factor
- **EMA Variance**: Incremental variance calculation
- **Variance Floor**: `variance_floor_factor=0.001` (0.1% of EMA²) prevents false positives during warmup when identical values produce near-zero variance
- **Z-Score Calculation**: `(value - ema) / sqrt(effective_variance)`

#### Detection Logic

```python
def check(self, backend_id: str, metric_name: str, value: float) -> Optional[float]:
    key = f"{backend_id}:{metric_name}"
    baseline = self.baselines[key]
    z = baseline.update(value)
    if baseline.count > 3 and abs(z) > self.z_threshold:  # z_threshold = 2.5
        return z  # Anomaly detected
    return None
```

The warmup period is 3 samples (~90 seconds at 30s update interval). The z-score threshold is 2.5 (configurable). The variance floor prevents the "warmup transient false positive" where perfectly stable metrics produce astronomical z-scores from tiny deviations.

#### Integration with Main Loop

In `main.py`, the baseline manager checks T1 and T2 coherence times for every qubit in every backend. Anomalies are assigned technique_id `QTT014` (Adaptive Baseline Anomaly). Stale baseline threats (from the previous cycle where the metric is no longer anomalous) are automatically removed.

---

## 10. Collectors Subsystem

### 10.1 BaseCollector ABC

```python
class BaseCollector(ABC):
    @abstractmethod
    async def collect(self) -> SimulationSnapshot:
        pass
```

All collectors implement this single-async-method interface.

### 10.2 MockCollector (`collectors/mock.py`)

Provides deterministic or randomized mock data for testing and demo mode.

- **Test Mode** (`is_test=True`): Returns fresh copies of `MOCK_DATA` with current timestamps. Fully deterministic — every call returns the same 4 backends (ibm_sherbrooke, ibm_kyoto, ibm_brisbane, ibm_qasm_simulator) and same 4 threats
- **Demo Mode** (`is_test=False`): Adds random variation to `api_surface_score` and `t1_us`, randomly adds/removes threats (20% chance per cycle)

### 10.3 IBMQuantumCollector (`collectors/ibm.py`)

Live collector connecting to IBM Quantum via Qiskit Runtime Service:

1. Authenticates with `QiskitRuntimeService(token=ibm_token, channel="ibm_quantum")`
2. Lists all backends and fetches status, configuration, properties
3. Extracts per-qubit calibration (T1, T2, readout error, CX gate error)
4. Fetches recent job history with circuit metadata (depth, gate histograms)
5. Computes `api_surface_score` based on qubit count and simulator status
6. Assigns `threat_level` based on calibration health (low T1 or high readout error)
7. **Degraded Mode**: On auth failure or error, returns cached snapshot with `degraded=True` metadata
8. **Value Guards**: Rejects physically implausible T1/T2 values (>10,000,000 µs)

### 10.4 AggregatorCollector (`collectors/aggregator.py`)

Runs multiple collectors concurrently via `asyncio.gather()` and merges results:

- Concatenates all backends across platforms
- Merges all threats
- Combines entanglement pairs
- Aggregates `platform_health` dict
- Computes combined severity counts and totals

### 10.5 GitHubTokenScanner (`collectors/github_scanner.py`)

Scans GitHub Code Search API for exposed IBM Quantum tokens:

- Search query: `QiskitRuntimeService+token+`
- Uses `httpx.AsyncClient` with 10s timeout
- Returns list of `{repo, file, pattern, url}` dicts
- Respects rate limits (403 → skip, 401 → warn)
- Only includes results with actual `text_matches` fragments (never fabricates placeholders)
- Runs every 5 minutes (300s) in the simulation loop to respect GitHub rate limits

### 10.6 ScenarioCollector (`collectors/scenario.py`)

Plays back pre-recorded attack sequences for demonstration. Three built-in scenarios:

1. **`recon`** — Progressive reconnaissance: calibration harvest → timing oracle → campaign correlation
2. **`credential_exploit`** — Credential exposure → timing oracle → pre-attack staging correlation
3. **`ddos_circuit`** — Resource exhaustion escalation across backends → resource abuse chain correlation

Each scenario is a list of snapshot steps that are played sequentially, looping back to the beginning when exhausted.

### 10.7 ThresholdCalibrator (`collectors/calibrator.py`)

Observes live IBM Quantum telemetry to learn empirical thresholds:

1. Runs the IBM collector every 30s for a configurable duration (default 60 minutes)
2. Records every metric used by detection rules
3. Computes p95-based recommended thresholds
4. Saves results to `calibration_results.json`

Key calibrations:
- `rule_002_calibration_harvest_ratio`: p95 * 1.5 (above normal but below attack)
- `rule_003_identity_gate_ratio`: p95 of identity gate ratios
- `rule_003_max_circuit_gates`: p5 of total gate counts (what "small" means)
- `rule_005_max_depth_ratio`: p95 of depth ratios
- `rule_008_t1_baseline_ratio`: p5 T1 / mean T1 (floor ratio)
- `rule_009_min_backends_accessed`: ceil(p95 of backends per window)
- `rule_010_measure_ratio`: p95 of measurement gate ratios

---

## 11. API Layer

### 11.1 REST Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Basic health check (status, demo mode, active collector, platforms) |
| GET | `/api/snapshot` | Optional | Full current `SimulationSnapshot` |
| GET | `/api/backends` | Optional | List of all `BackendNode` objects |
| GET | `/api/threats` | Optional | Active threats (filterable by `?severity=`) |
| GET | `/api/threat/{threat_id}` | Optional | Single threat detail (validated input) |
| GET | `/api/threats/export/stix` | Optional | STIX 2.1 Bundle export (paginated: `?limit=&offset=`) |
| GET | `/api/threats/history` | Optional | Paginated threat history from SQLite |
| GET | `/api/threats/stats` | Optional | Aggregated statistics (by severity, platform, technique) |
| POST | `/api/scenario/load` | Optional | Load a named scenario |
| GET | `/api/scenario/list` | No | List available scenarios |
| POST | `/api/scenario/reset` | Optional | Reset to default collector |
| GET | `/{full_path:path}` | No | SPA fallback (serves frontend) |

### 11.2 WebSocket Endpoint

**Path**: `/ws/simulation`  
**Protocol**: WebSocket over `ws://` or `wss://`

Authentication: If `AUTH_ENABLED=true`, the client must pass `?token=<api_key>` in the query string.

Client → Server messages:
```json
{"type": "get_snapshot"}          // Request current snapshot
{"type": "focus_backend", "backend_id": "ibm_sherbrooke"}  // Focus on a backend
{"type": "ping"}                  // Heartbeat
```

Server → Client messages: Full `SimulationSnapshot` JSON on every broadcast cycle.

### 11.3 Static File Serving

The `/{full_path:path}` catch-all route serves the SPA frontend:
- Checks for static files in `frontend/` directory
- Blocks null bytes, path traversal (`..`), and reserved paths (`docs`, `redoc`, `openapi.json`)
- Falls back to `index.html` for SPA routing
- Uses `mimetypes.guess_type()` for correct Content-Type headers

---

## 12. Security Layer

### 12.1 Authentication (`api/auth.py`)

API key authentication via `X-API-Key` header using SHA-256 hashing:

```python
async def verify_api_key(request, api_key=Depends(API_KEY_HEADER)):
    if not settings.auth_enabled:
        return None  # Auth disabled — allow all
    if secrets.compare_digest(_hash_key(api_key), _get_hashed_key()):
        return True
    raise HTTPException(status_code=403, detail="Invalid API key")
```

Uses `secrets.compare_digest()` for constant-time comparison to prevent timing attacks.

### 12.2 Security Headers (`api/security_headers.py`)

Applied to every HTTP response:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Block unnecessary browser APIs |
| `Content-Security-Policy` | Multi-directive | XSS protection (see below) |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
| `Cache-Control` | `no-store` (API only) | Prevent caching of real-time threat data |

**CSP Directives**:
- `default-src 'self'` — Only same-origin by default
- `script-src 'self' cdn... 'unsafe-inline' blob:` — CDN scripts + inline shaders + Swagger workers
- `style-src 'self' 'unsafe-inline'` — Inline styles for Three.js
- `connect-src 'self' ws: wss:` — WebSocket connections
- `frame-ancestors 'none'` — No framing
- `form-action 'self'` — Forms only to same origin

### 12.3 Rate Limiting (`api/ratelimit.py`)

Weighted sliding-window rate limiter with memory management:

- **Algorithm**: Weighted sliding window — `prev_count * (1 - position) + curr_count >= max_requests`
- **Scope**: Only `/api/*` routes
- **Defaults**: 60 requests per 60 seconds (configurable via `RATE_LIMIT`)
- **Memory Management**: Max 10,000 tracked IPs with automatic pruning
- **IP Validation**: Rejects malformed client identifiers
- **Response Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`

### 12.4 WebSocket Security

- **Max Connections**: 200 (`MAX_CONNECTIONS`)
- **Max Message Size**: 256 KB (`MAX_MESSAGE_SIZE`)
- **Rate Limiting**: 60 messages per minute per client (`MAX_MESSAGES_PER_MINUTE`)
- **Message Validation**: `validate_message()` checks size and rate before processing
- **Auth**: Optional token authentication via query parameter

---

## 13. Storage Layer

### 13.1 SQLite Database (`storage/database.py`)

Uses `aiosqlite` with WAL (Write-Ahead Logging) mode for concurrent read performance:

```python
await _connection.execute("PRAGMA journal_mode=WAL;")
await _connection.execute("PRAGMA synchronous=NORMAL;")
```

#### Schema

**`threat_events` table**:

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | ThreatEvent UUID |
| `technique_id` | TEXT NOT NULL | Q-ATT&CK technique ID |
| `severity` | TEXT NOT NULL | Severity level |
| `platform` | TEXT NOT NULL | Platform enum value |
| `backend_id` | TEXT | Backend identifier |
| `title` | TEXT NOT NULL | Short title |
| `description` | TEXT NOT NULL | Detailed description |
| `evidence` | TEXT NOT NULL | JSON evidence dict |
| `detected_at` | TEXT NOT NULL | ISO-8601 timestamp |
| `visual_effect` | TEXT NOT NULL | Visual effect name |
| `visual_intensity` | REAL NOT NULL | 0.0–1.0 intensity |
| `remediation` | TEXT NOT NULL | JSON array of strings |
| `resolved_at` | TEXT | ISO-8601 timestamp or NULL |

**`correlation_events` table**:

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Campaign event UUID |
| `pattern_name` | TEXT NOT NULL | Correlation pattern name |
| `techniques` | TEXT NOT NULL | JSON array of technique IDs |
| `backends` | TEXT NOT NULL | JSON array of backend IDs |
| `detected_at` | TEXT NOT NULL | ISO-8601 timestamp |
| `severity` | TEXT NOT NULL | Escalated severity |

#### Indexes

- `idx_threats_detected_at` — Fast time-ordered queries
- `idx_threats_severity` — Severity filtering
- `idx_threats_technique_id` — Technique-based queries
- `idx_threats_backend_id` — Backend-specific queries
- `idx_threats_resolved_at` — Active vs resolved queries
- `idx_corr_detected_at` — Correlation time queries

#### Key Operations

- `save_threat()` — INSERT OR REPLACE (upsert)
- `resolve_threat()` — UPDATE resolved_at (only if currently NULL)
- `get_threats()` — Paginated query with optional severity filter
- `get_threat_stats()` — Aggregate counts by severity, platform, technique
- `save_correlation()` / `get_correlations()` — Correlation event CRUD

---

## 14. Frontend Architecture

### 14.1 Technology Stack

- **No build tools** — Pure vanilla JavaScript (ES modules)
- **Three.js r128** — 3D rendering engine (loaded from CDN)
- **Post-processing** — UnrealBloomPass for glow effects (graceful fallback)
- **Tween.js** — Smooth camera animations (optional, graceful fallback)
- **No framework** — No React, Vue, or Angular

### 14.2 Initialization Sequence (`js/main.js`)

1. **`bootstrap()`** — Entry point called immediately on module load
2. **Stage 1: Detect** — `FallbackManager.detectCapabilities()` checks WebGL, WASM, etc.
3. **Stage 2: Validate** — `validateCriticalScripts()` checks CDN script availability
4. **Stage 3: Initialize** — Either `initThreeJS()` or `initCanvas2D()` (fallback)
5. **Stage 4: Connect** — `initWebSocket()` establishes WebSocket connection
6. **On first snapshot** — Loading screen fades out, visualization begins

### 14.3 Module Organization

**Core** (`js/core/`):
- `FallbackManager.js` — Browser capability detection, global error handlers, snapshot caching for offline use, diagnostic reporting
- `AudioEngine.js` — Web Audio API for alert sounds (critical/high threat detected)
- `PerformanceMonitor.js` — FPS counter, draw calls, triangle count
- `ToastManager.js` — Toast notification system (info/warning/error/success)

**Data** (`js/data/`):
- `WSClient.js` — WebSocket client with auto-reconnect (exponential backoff), connection state machine (`CONNECTED`, `RECONNECTING`, `OFFLINE`)
- `StateMapper.js` — Maps `SimulationSnapshot` to Three.js scene: creates/updates/removes `Backend` nodes, updates particles, entanglement, threat visuals

**Simulation** (`js/simulation/`):
- `Backend.js` — 3D representation of a quantum backend (icosahedron geometry + orbital rings, color-coded by platform, pulsing by threat level)
- `ParticleSystem.js` — GPU-friendly particle effects for threat visualization (leak, drain, interference, timing ring, vortex, campaign)
- `Entanglement.js` — Renders bezier curve connections between entangled backend pairs
- `ThreatVisuals.js` — Manager for per-backend threat visual effects (attaches/removes visual effects based on active threats)

**UI** (`js/ui/`):
- `HUD.js` — Top bar displaying: total backends, total qubits, active threats count, platform indicators, update interval
- `ThreatPanel.js` — Right-side panel showing threat list and detail view
- `Legend.js` — Bottom-left legend showing severity colors, platform colors, and visual effect types
- `Timeline.js` — Event timeline (placeholder for future implementation)
- `Controls.js` — Wraps Three.js orbit controls with idle auto-rotation

**Renderers** (`js/renderers/`):
- `Canvas2DFallback.js` — Complete 2D visualization using HTML5 Canvas for browsers without WebGL

### 14.4 Event-Driven Architecture

The frontend uses `CustomEvent` for decoupled communication:

- `snapshotUpdate` — Dispatched when a new snapshot is received from WebSocket
- `backendSelected` — Dispatched when user clicks a backend node
- `wsStateChange` — Dispatched on WebSocket state transitions

### 14.5 Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Esc` | Close threat panel, reset camera |
| `R` | Reset camera view |
| `Space` | Toggle auto-rotation |
| `+` / `-` | Zoom in/out |
| `Ctrl+F` | Toggle FPS counter |
| `Ctrl+D` | Toggle diagnostic report |
| `H` | Toggle HUD |
| `M` | Toggle audio |
| `?` | Show help |

---

## 15. WebSocket Protocol

### 15.1 Connection

```
ws://<host>/ws/simulation[?token=<api_key>]
```

### 15.2 Server → Client

Every 30 seconds (or `UPDATE_INTERVAL_SECONDS`), the server broadcasts a complete `SimulationSnapshot` as JSON:

```json
{
  "snapshot_id": "uuid",
  "generated_at": "2026-04-18T12:00:00Z",
  "backends": [...],
  "threats": [...],
  "entanglement_pairs": [...],
  "total_qubits": 413,
  "total_threats": 4,
  "threats_by_severity": {"critical": 1, "high": 1, "medium": 2},
  "platform_health": {"ibm_quantum": 0.75}
}
```

### 15.3 Client → Server

```json
{"type": "get_snapshot"}
{"type": "focus_backend", "backend_id": "ibm_sherbrooke"}
{"type": "ping"}
```

### 15.4 Error Handling

- Invalid JSON → warning logged, message ignored
- Unknown message type → warning logged, message ignored
- Message too large (>256KB) → message rejected
- Rate exceeded (>60/min) → message rejected

---

## 16. Configuration System

### 16.1 Environment Variables

All configuration is loaded from `.env` file via `pydantic-settings`. See Section 5.2 for the complete settings table.

### 16.2 Calibration File

`calibration_results.json` (auto-generated by `--calibrate` CLI mode):

```json
{
  "calibrated_at": "2026-04-18T12:00:00Z",
  "duration_minutes": 60,
  "samples_collected": 120,
  "backends_observed": ["ibm_sherbrooke", "ibm_kyoto"],
  "rule_002_calibration_harvest_ratio": 4.5,
  "rule_003_identity_gate_ratio": 0.65,
  ...
}
```

### 16.3 CLI Mode

```bash
python -m backend.main --calibrate [duration_minutes]
```

Runs the live IBM Quantum collector, computes p95-based thresholds, saves to `calibration_results.json`, and exits.

---

## 17. Simulation Loop (Main Pipeline)

The `simulation_loop()` in `main.py` is the heartbeat of the system. It runs as an `asyncio.Task` and executes the following pipeline every `UPDATE_INTERVAL_SECONDS` (default 30s):

```
1. COLLECT      ── collector.collect() → SimulationSnapshot
2. GITHUB SCAN  ── github_scanner.scan_for_ibm_tokens() (every 5 min)
3. ANALYZE      ── analyzer.analyze(snapshot) → enriched snapshot
4. GITHUB RULE  ── RULE_001 against github results → merge new threats
5. BASELINE     ── baseline_manager.check() per qubit per metric → QTT014 threats
6. CORRELATE    ── correlator.correlate(threats) → campaign events
7. PERSIST      ── analyzer.persist_new_threats() + resolve_disappeared_threats()
8. PERSIST CORR── save_correlation() for campaign events
9. SNAPSHOT     ── Atomic swap of latest_snapshot (copy-on-write)
10. BROADCAST   ── manager.broadcast_snapshot(enriched_snapshot)
11. SLEEP       ── asyncio.sleep(update_interval_seconds)
```

**Error handling**: Any exception in the loop is caught, logged, and the loop sleeps 5 seconds before retrying. `asyncio.CancelledError` breaks the loop cleanly.

**Copy-on-write**: The `latest_snapshot` global is updated atomically using `asyncio.Lock` and `model_copy(deep=False)` so API reads never observe a partially-mutated snapshot.

---

## 18. Q-ATT&CK Framework Mapping

QVis uses a custom **Q-ATT&CK** (Quantum Adversarial Tactics, Techniques, and Common Knowledge) framework that adapts MITRE ATT&CK for quantum computing infrastructure.

### Technique ID → Rule Mapping

| Q-ATT&CK ID | Rule Function | Name |
|-------------|---------------|------|
| QTT001 | RULE_009 | Multi-Backend Reconnaissance |
| QTT002 | RULE_002 | Calibration Harvesting |
| QTT003 | RULE_003 | Timing Oracle |
| QTT004 | RULE_004 | Tenant Probing |
| QTT005 | RULE_007 | Scope Violation |
| QTT006 | RULE_006 | IP Extraction |
| QTT007 | RULE_001 | Credential Exposure |
| QTT008 | RULE_005 | Resource Exhaustion |
| QTT009 | RULE_010 | Anomalous Circuit |
| QTT010 | RULE_008 | Hardware Degradation |
| QTT014 | (main.py) | Adaptive Baseline Anomaly |

### MITRE ATT&CK Mapping

Each Q-ATT&CK technique maps to a MITRE ATT&CK tactic and technique:

- **Credential Access** (TA0006): QTT002, QTT007
- **Discovery** (TA0007): QTT003, QTT004, QTT009
- **Initial Access** (TA0001): QTT005
- **Exfiltration** (TA0010): QTT006
- **Impact** (TA0040): QTT008
- **Collection** (TA0009): QTT010

---

## 19. Scenario Playback System

### 19.1 Architecture

Scenarios are pre-recorded attack sequences stored as lists of snapshot dicts. The `ScenarioCollector` plays them back step by step:

```python
SCENARIOS = {
    "recon": _build_recon_scenario,           # 4 steps
    "credential_exploit": _build_credential_exploit_scenario,  # 4 steps
    "ddos_circuit": _build_ddos_circuit_scenario,  # 4 steps
}
```

### 19.2 API

```bash
POST /api/scenario/load?name=recon    # Load scenario
GET  /api/scenario/list                # List available
POST /api/scenario/reset               # Reset to default mock
```

### 19.3 Scenario Design

Each scenario tells a progressive story:
- **Step 1**: Clean baseline (no threats)
- **Step 2**: First threat appears
- **Step 3**: Second threat appears (different technique)
- **Step 4**: Campaign correlation detected (both techniques + correlated event)

This demonstrates the full detection pipeline from individual rules to campaign correlation.

---

## 20. Threshold Calibration

### 20.1 Overview

The `ThresholdCalibrator` observes live IBM Quantum telemetry to learn empirical thresholds that replace the hardcoded conservative defaults in `rules.py`.

### 20.2 Process

1. Collect snapshots every 30s for configurable duration (default 60 min)
2. Extract all metrics used by detection rules from each snapshot
3. Compute per-metric p95 (or p5 where appropriate) across all samples
4. Apply scaling factors (e.g., p95 * 1.5 for calibration harvest ratio)
5. Save results to `calibration_results.json`
6. On next startup, `load_threshold_config_from_file()` loads and applies these thresholds

### 20.3 Calibration Metrics

| Rule | Metric | Calculation |
|------|--------|-------------|
| RULE_002 | Calibration harvest ratio | `cal_requests / max(jobs, 1)` → p95 * 1.5 |
| RULE_003 | Identity gate ratio | `id_count / total_gates` → p95 |
| RULE_003 | Max circuit gates | Total gates → p5 (small end) |
| RULE_005 | Depth ratio | `depth / max_depth` → p95 |
| RULE_008 | T1 baseline ratio | `p5_t1 / mean_t1` |
| RULE_009 | Backends per window | Unique backends → ceil(p95) |
| RULE_010 | Measure ratio | `measure_count / total` → p95 |
| RULE_010 | Min circuit gates | Total gates → p5 |

---

## 21. STIX Export

### 21.1 Format

QVis exports threats as STIX 2.1 Bundles via `GET /api/threats/export/stix`.

### 21.2 Implementation (`api/export.py`)

Each `ThreatEvent` is converted to a STIX 2.1 Indicator:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid5>",
  "created": "...",
  "modified": "...",
  "name": "threat title",
  "description": "threat description",
  "indicator_types": ["anomalous-activity"],
  "pattern": "[x-quantum-threat:technique_id = 'QTT003']",
  "pattern_type": "stix",
  "valid_from": "...",
  "labels": ["high", "ibm_quantum"],
  "confidence": 80,
  "extensions": {
    "x-qvis-threat": {
      "backend_id": "...",
      "visual_effect": "...",
      "visual_intensity": 0.7,
      "remediation": [...],
      "evidence": {...}
    }
  }
}
```

### 21.3 Features

- **Stable IDs**: UUID5-based STIX IDs (deterministic from threat ID)
- **LRU Cache**: 5,000-entry cache prevents unbounded memory growth
- **Content-hash Bundles**: Deterministic bundle IDs based on threat content
- **Pagination**: `?limit=N&offset=M` support
- **Confidence Mapping**: Severity → confidence score (critical=95, high=80, medium=60, low=40, info=20)

---

## 22. Deployment & Containerization

### 22.1 Dockerfile

Multi-stage build with security hardening:

- **Stage 1 (builder)**: Installs Python dependencies into `/install`
- **Stage 2 (runtime)**: Copies dependencies, creates non-root user `qvis:qvis`, sets `WORKDIR /app`

Security features:
- Non-root user (`USER qvis`)
- No-new-privileges (`security_opt: no-new-privileges:true`)
- Read-only filesystem (`read_only: true`) with tmpfs at `/tmp`
- Resource limits (2 CPU, 512M memory)
- Health check against `/api/health`

### 22.2 Docker Compose

```yaml
services:
  qvis:
    build: .
    ports: ["8000:8000"]
    volumes: ["qvis-data:/app/.qvis-data"]
    environment:
      - DEMO_MODE=true
      - UPDATE_INTERVAL_SECONDS=30
      - AUTH_ENABLED=false
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; ..."]
```

### 22.3 Entrypoint

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

---

## 23. Testing Strategy

### 23.1 Test Organization

Tests are in `qvis/tests/` with pytest and pytest-asyncio (asyncio_mode=auto).

### 23.2 Shared Fixtures (`conftest.py`)

Two `autouse=True` fixtures ensure test isolation:

1. **`_reset_threshold_config`** — Clears global `ThresholdConfig` before/after each test
2. **`_reset_rate_limiter_state`** — Clears global rate limiter state before/after each test

Common fixtures:
- `sample_ibm_backend` — 5-qubit IBM backend
- `normal_calibration_data` — Baseline calibration for 5 qubits
- `sample_threat_events` — 5 diverse threat events
- `mock_snapshot` — Empty snapshot with one backend

### 23.3 Test Categories

| File | Tests | Focus |
|------|-------|-------|
| `test_rules.py` | 80+ | All 10 detection rules: positive, negative, threshold, evidence, enabled_rules, dict mode |
| `test_baseline_manager.py` | 10+ | EMA, z-scores, variance floor, warmup |
| `test_correlator.py` | 15+ | All 4 correlation patterns, dedup, expiry |
| `test_threat_engine.py` | 20+ | Full pipeline integration |
| `test_collectors.py` | 10+ | Mock, aggregator, IBM collector |
| `test_github_scanner.py` | 5+ | GitHub token scanning |
| `test_api.py` | 20+ | All REST endpoints, auth, rate limiting |
| `test_defcon_hardening.py` | 10+ | Security hardening (CSP, input validation, etc.) |
| `test_scenario.py` | 5+ | Scenario loading and playback |
| `test_e2e.py` | 5+ | End-to-end flow |
| `test_regression_all_fixes.py` | 10+ | Full regression suite |

### 23.4 Quality Gates

Every detection rule must have at minimum 8 tests:
1. **Positive case** — Rule fires when threshold exceeded
2. **Negative case (below)** — Rule does NOT fire below threshold
3. **Negative case (empty)** — Rule handles empty/no-data gracefully
4. **Threshold override** — Custom threshold via `ThresholdConfig` works
5. **Evidence schema** — Evidence contains `rule_name` and `threshold_used`
6. **Valid technique_id** — `technique_id` is a valid Q-ATT&CK ID
7. **Enabled rules** — Rule skips when disabled in `enabled_rules`
8. **Dict mode** — Rule works with raw dict input (not just Pydantic model)

### 23.5 Running Tests

```bash
cd qvis
pytest tests/ -v --tb=short          # All tests
pytest tests/test_rules.py -v        # Rule tests only
USE_MOCK=true pytest tests/ -v       # With mock collector
```

Total: **114 tests** (all passing as of latest commit)

---

## 24. Design Decisions & Quality Gates

### 24.1 Quality Gates

| ID | Gate | Status |
|----|------|--------|
| G1 | Pure functions for rules (no side effects) | Enforced |
| G2 | Dict-mode compatibility (rules accept raw dicts) | Enforced |
| G3 | Evidence always contains `rule_name` | Enforced (G6) |
| G4 | Evidence always contains `threshold_used` | Enforced (G6) |
| G5 | All thresholds go through `_cfg()` | Enforced |
| G6 | Evidence dict has `rule_name` + `threshold_used` | Enforced |
| G7 | `enabled_rules` field in ThresholdConfig | Enforced |

### 24.2 Key Design Decisions

1. **Dict-mode rules** — Rules accept raw dicts, not Pydantic models. This allows `SimulationSnapshot.model_dump()` to be passed directly without constructing a separate data structure. The snapshot's `extra="allow"` config lets collectors inject telemetry fields that rules can access.

2. **Copy-on-write snapshots** — `latest_snapshot` is replaced atomically using `asyncio.Lock` and `model_copy(deep=False)`. This prevents API reads from seeing partially-updated snapshots during the simulation loop.

3. **Differential persistence** — The analyzer tracks `_persisted_ids` to avoid redundant database INSERTs. Only genuinely new threats are persisted. Disappeared threats are automatically marked resolved.

4. **Variance floor** — The baseline manager enforces a minimum variance floor (0.1% of EMA²) to prevent false positives during the warmup period when perfectly stable metrics would produce astronomical z-scores.

5. **Campaign dedup** — The correlator uses a separate `_campaign_dedup` set (independent from `recent_threats`) so that pruning old events doesn't allow the same campaign to re-fire within the correlation window.

6. **No build tools for frontend** — Pure ES modules loaded from CDN. This minimizes complexity and avoids Node.js dependency for the frontend. Trade-off: no tree-shaking, no TypeScript.

7. **Graceful degradation** — Three.js, bloom, and Tween.js are all loaded with `onerror` handlers that set `window.__*Unavailable` flags. The `FallbackManager` detects capabilities and falls back to 2D Canvas rendering if WebGL is unavailable.

8. **SecretStr everywhere** — All credentials use `pydantic.SecretStr` which prevents accidental logging, repr(), or serialization of secret values.

9. **Structlog throughout** — All logging uses `structlog` with keyword arguments (no f-strings in log calls). Supports JSON output for production log aggregation.

10. **WAL mode SQLite** — Write-Ahead Logging allows concurrent reads while writes are in progress, critical for the async simulation loop + API serving pattern.

---

## Appendix A: Dependency Graph

```
backend/main.py
├── backend/config.py (Settings)
├── backend/api/websocket.py (ConnectionManager)
├── backend/api/auth.py (verify_api_key)
├── backend/api/security_headers.py (SecurityHeadersMiddleware)
├── backend/api/ratelimit.py (RateLimitMiddleware)
├── backend/api/export.py (export_stix_bundle)
├── backend/threat_engine/analyzer.py (ThreatAnalyzer)
│   ├── backend/threat_engine/rules.py (ALL_RULES, get_active_rules)
│   └── backend/storage/database.py (save_threat, resolve_threat)
├── backend/threat_engine/correlator.py (ThreatCorrelator)
├── backend/threat_engine/baseline.py (BaselineManager)
├── backend/threat_engine/models.py (SimulationSnapshot, ThreatEvent, etc.)
├── backend/threat_engine/rules.py (load_threshold_config_from_file)
├── backend/storage/database.py (init_db, close_db)
└── backend/collectors/
    ├── base.py (BaseCollector)
    ├── mock.py (MockCollector)
    ├── ibm.py (IBMQuantumCollector)
    ├── braket.py (BraketCollector)
    ├── azure_quantum.py (AzureQuantumCollector)
    ├── aggregator.py (AggregatorCollector)
    ├── github_scanner.py (GitHubTokenScanner)
    ├── scenario.py (ScenarioCollector)
    └── calibrator.py (ThresholdCalibrator)
```

## Appendix B: Visual Effects

| Effect Name | Description | Triggered By |
|-------------|-------------|-------------|
| `particle_leak` | Red particles escaping outward | QTT007 Credential Exposure |
| `calibration_drain` | Green funnel draining down | QTT002 Calibration Harvesting, QTT010 Hardware Degradation |
| `timing_ring` | Expanding orange rings | QTT003 Timing Oracle |
| `color_bleed` | Foreign color particles | QTT004 Tenant Probing, QTT009 Multi-Backend Recon |
| `interference` | Static/chaotic lines | QTT005 Scope Violation, QTT008 Resource Exhaustion, QTT009 Anomalous Circuit |
| `vortex` | Dark sphere and disc | QTT006 IP Extraction |
| `campaign` | Campaign visual | Correlation patterns |

---

*QVIS_ARCHITECTURE.md — Complete System Architecture Reference*
*QVis Quantum Threat Intelligence Visualization System*
*Generated: 2026-04-18*
