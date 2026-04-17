# QVis — Quantum Threat Intelligence Visualization System

## Complete Architecture Reference Document

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [System Architecture](#2-system-architecture)
3. [Directory Structure](#3-directory-structure)
4. [Backend Architecture (Python/FastAPI)](#4-backend-architecture-pythonfastapi)
   - 4.1 [Data Models](#41-data-models)
   - 4.2 [Threat Engine](#42-threat-engine)
   - 4.3 [Detection Rules](#43-detection-rules)
   - 4.4 [Baseline & Anomaly Detection](#44-baseline--anomaly-detection)
   - 4.5 [Cross-Rule Correlation](#45-cross-rule-correlation)
   - 4.6 [Threat Analyzer (Orchestrator)](#46-threat-analyzer-orchestrator)
   - 4.7 [Collectors Layer](#47-collectors-layer)
   - 4.8 [API Layer](#48-api-layer)
   - 4.9 [Storage Layer](#49-storage-layer)
   - 4.10 [Configuration](#410-configuration)
5. [Frontend Architecture (Vanilla JS + Three.js)](#5-frontend-architecture-vanilla-js--threejs)
   - 5.1 [Application Bootstrap](#51-application-bootstrap)
   - 5.2 [Data Pipeline](#52-data-pipeline)
   - 5.3 [3D Simulation Layer](#53-3d-simulation-layer)
   - 5.4 [UI Components](#54-ui-components)
   - 5.5 [Core Infrastructure](#55-core-infrastructure)
   - 5.6 [2D Fallback Renderer](#56-2d-fallback-renderer)
6. [Data Flow & Event System](#6-data-flow--event-system)
7. [Q-ATT&CK Threat Taxonomy](#7-q-attack-threat-taxonomy)
8. [Security Hardening](#8-security-hardening)
9. [Deployment](#9-deployment)
10. [Testing Strategy](#10-testing-strategy)

---

## 1. Executive Overview

**QVis** (Quantum Threat Intelligence Visualization System) is a real-time, 3D interactive threat intelligence platform designed for monitoring, detecting, and visualizing security threats against quantum computing infrastructure. Originally built for DEF CON cybersecurity conferences, it provides a visually compelling, data-driven dashboard that ingests live telemetry from multiple quantum computing platforms (IBM Quantum, Amazon Braket, Azure Quantum) and applies a custom threat detection engine modeled after the MITRE ATT&CK framework but adapted for quantum-specific attack vectors.

The system follows a **multi-tier pipeline architecture**: raw telemetry is collected from quantum cloud providers, enriched with detection rules from the Q-ATT&CK threat taxonomy, correlated across rules to identify multi-stage campaigns, persisted to a database for historical analysis, and finally broadcast via WebSocket to a browser-based 3D visualization rendered with Three.js (with a Canvas 2D fallback for environments without WebGL).

Key design principles:
- **Pure-function detection rules**: Every rule is `(dict) -> list[ThreatEvent]` with zero side effects
- **Configurable thresholds**: A `ThresholdConfig` dataclass allows all detection thresholds to be overridden without code changes, loaded from `calibration_results.json` produced by a separate calibration mode
- **Adaptive baselines**: An EMA-based baseline manager with configurable variance floor detects statistical anomalies in qubit coherence metrics
- **Campaign correlation**: Four predefined correlation patterns detect multi-stage attacks when specific technique pairs appear on the same backend within a time window
- **Graceful degradation**: The frontend detects WebGL capability, validates CDN scripts, and falls back to a 2D canvas renderer while caching snapshots for offline viewing
- **DEFCON-grade hardening**: Rate limiting, API key auth, security headers, path traversal protection, input sanitization, and sliding-window WebSocket abuse prevention

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          BROWSER (Frontend)                             │
│                                                                          │
│  ┌──────────┐  ┌────────────┐  ┌───────────────┐  ┌───────────────┐   │
│  │ WSClient │─→│StateMapper │─→│ 3D Scene       │  │ UI Components │   │
│  └──────────┘  └────────────┘  │ ┌───────────┐ │  │ ┌───────────┐ │   │
│       ▲           │             │ │ Backend    │ │  │ │ HUD       │ │   │
│       │           │             │ │ Particles  │ │  │ │ ThreatPanel│ │   │
│  WebSocket       │             │ │ Entangle.  │ │  │ │ Timeline  │ │   │
│       │           ▼             │ │ ThreatVis  │ │  │ │ Legend    │ │   │
│  ┌──────────────────────────┐  │ └───────────┘ │  │ │ Controls  │ │   │
│  │  FastAPI Backend (:8000) │  └───────────────┘  │ │ Audio     │ │   │
│  │                          │       ▲             │ └───────────┘ │   │
│  │  ┌─────────────────┐   │       │             └───────────────┘   │
│  │  │ Threat Engine    │   │       │                                   │
│  │  │ ┌─────────────┐ │   │  simulation_loop()                      │
│  │  │ │ 10 Rules     │ │   │       │                                   │
│  │  │ │ Q-ATT&CK     │ │   │  ┌────┴────┐                              │
│  │  │ └──────┬──────┘ │   │  │Collector │                              │
│  │  │        │        │   │  │ ┌──────┐ │                              │
│  │  │ ┌──────▼──────┐ │   │  │ │IBM   │ │                              │
│  │  │ │ Correlator   │ │   │  │ │Braket│ │                              │
│  │  │ └─────────────┘ │   │  │ │Azure │ │                              │
│  │  │ ┌─────────────┐ │   │  │ │Mock  │ │                              │
│  │  │ │ Baseline Mgr │ │   │  │ └──────┘ │                              │
│  │  │ └─────────────┘ │   │  │ Aggregator│                              │
│  │  │ ┌─────────────┐ │   │  └──────────┘                              │
│  │  │ │ Analyzer     │─┼───┤                                          │
│  │  │ └─────────────┘ │   │  ┌──────────┐                              │
│  │  └─────────────────┘   │  │SQLite DB │                              │
│  │                          │  │(aiosqlite│                              │
│  │  /api/* endpoints       │  │ WAL mode)│                              │
│  │  /ws/simulation         │  └──────────┘                              │
│  └──────────────────────────┘                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Interaction Summary

The system operates on a **continuous polling loop** (`simulation_loop()` in `main.py`):

1. **Collect**: The active collector fetches telemetry from one or more quantum platforms
2. **Analyze**: The `ThreatAnalyzer` runs all 10 active detection rules against the raw data
3. **Enrich**: GitHub scanner results (RULE_001) are injected separately on a 5-minute cycle
4. **Baseline Check**: Per-qubit T1/T2 coherence metrics are checked against adaptive EMA baselines
5. **Correlate**: The `ThreatCorrelator` checks if any detected technique pairs match campaign patterns
6. **Persist**: New threats are INSERT-ed into SQLite; resolved threats get `resolved_at` timestamps
7. **Broadcast**: The enriched `SimulationSnapshot` is serialized to JSON and pushed to all WebSocket clients
8. **Sleep**: The loop sleeps for `update_interval_seconds` (default 30s)

---

## 3. Directory Structure

```
qvis/
├── backend/                          # Python backend (FastAPI application)
│   ├── __init__.py
│   ├── main.py                       # FastAPI app entry, simulation loop, all API endpoints
│   ├── config.py                     # Settings (pydantic-settings, env vars)
│   ├── threat_engine/                # Detection engine
│   │   ├── __init__.py
│   │   ├── models.py                 # Pydantic data models (Severity, Platform, ThreatEvent, etc.)
│   │   ├── rules.py                  # 10 pure-function detection rules + ThresholdConfig
│   │   ├── baseline.py               # EMA baseline manager + MetricBaseline
│   │   ├── correlator.py             # Cross-rule campaign correlation (4 patterns)
│   │   └── analyzer.py               # Orchestrator: runs rules, persists, resolves threats
│   ├── collectors/                   # Data collection from quantum platforms
│   │   ├── __init__.py
│   │   ├── base.py                   # Abstract BaseCollector (collect() -> SimulationSnapshot)
│   │   ├── mock.py                   # MockCollector for demo/testing
│   │   ├── ibm.py                    # IBMQuantumCollector (live Qiskit Runtime)
│   │   ├── braket.py                 # BraketCollector (AWS Braket devices)
│   │   ├── azure_quantum.py          # AzureQuantumCollector (Azure Quantum targets)
│   │   ├── aggregator.py             # AggregatorCollector (parallel multi-platform merge)
│   │   ├── github_scanner.py         # GitHubTokenScanner (RULE_001 data source)
│   │   ├── calibrator.py             # ThresholdCalibrator (p95-based threshold learning)
│   │   └── scenario.py               # ScenarioCollector (3 pre-recorded attack sequences)
│   ├── api/                          # HTTP/WS API layer
│   │   ├── __init__.py
│   │   ├── auth.py                   # API key authentication (SHA-256, constant-time)
│   │   ├── websocket.py              # ConnectionManager (max 200, rate-limited)
│   │   ├── security_headers.py       # CSP, HSTS, X-Content-Type-Options, etc.
│   │   ├── ratelimit.py             # Sliding-window rate limiter (weighted)
│   │   └── export.py                 # STIX 2.1 threat intelligence export
│   └── storage/                      # Persistence layer
│       ├── __init__.py
│       └── database.py               # Async SQLite (aiosqlite, WAL mode)
├── frontend/                         # Vanilla JS frontend
│   ├── index.html                    # SPA shell, CDN scripts, loading screen
│   ├── css/
│   │   └── main.css                  # 638-line DEF CON dark theme stylesheet
│   └── js/
│       ├── main.js                   # Application bootstrap + render loop
│       ├── state.js                  # Shared appState (camera, controls, isAnimatingCamera)
│       ├── utils.js                  # sanitize() XSS helper
│       ├── data/
│       │   ├── WSClient.js           # WebSocket client with reconnection + heartbeat
│       │   └── StateMapper.js        # Snapshot-to-3D-scene mapper + raycasting
│       ├── simulation/
│       │   ├── Backend.js            # Quantum backend 3D node (sphere + rings + label)
│       │   ├── Entanglement.js       # Quantum entanglement tube renderer
│       │   ├── ThreatVisuals.js      # 7 threat visual effect types
│       │   └── ParticleSystem.js     # GPU orbital particle system (2000 max)
│       ├── ui/
│       │   ├── HUD.js                # Heads-up display (stats, ticker, status pills)
│       │   ├── Controls.js           # Spherical coordinate orbit camera controller
│       │   ├── ThreatPanel.js        # Slide-in detail panel (evidence, remediation)
│       │   ├── Timeline.js           # Bottom chronological threat timeline
│       │   └── Legend.js             # Platform + threat visual legend panel
│       ├── core/
│       │   ├── FallbackManager.js    # Capability detection + graceful degradation
│       │   ├── AudioEngine.js        # Procedural Web Audio API sound engine
│       │   ├── PerformanceMonitor.js # FPS counter + frame time stats
│       │   └── ToastManager.js       # Stacked notification toasts
│       └── renderers/
│           └── Canvas2DFallback.js   # 2D canvas fallback renderer
├── tests/                            # 322+ test cases
│   ├── __init__.py
│   ├── conftest.py                   # Shared fixtures + autouse config/rate limiter reset
│   ├── test_rules.py                 # 80 tests: all 10 rules + ThresholdConfig + evidence + enabled_rules
│   ├── test_correlator.py            # 19 tests: 4 patterns + dedup + pruning + isolation
│   ├── test_baseline_manager.py      # 15 tests: EMA + warmup + anomaly + drift + variance floor
│   ├── test_threat_engine.py         # Integration tests for the full engine pipeline
│   ├── test_api.py                   # REST API endpoint tests
│   ├── test_e2e.py                   # End-to-end flow tests
│   ├── test_phase1.py                # Phase 1 regression tests
│   ├── test_phase2.py                # Phase 2 regression tests
│   ├── test_priority_fixes.py        # Priority defect fixes
│   ├── test_integration_fixes.py     # Integration-level fix validation
│   ├── test_regression_all_fixes.py  # Master regression suite
│   ├── test_defcon_hardening.py      # DEFCON security hardening tests
│   ├── test_collectors.py            # Collector strategy tests
│   ├── test_github_scanner.py        # GitHub token scanner tests
│   ├── test_scenario.py              # Scenario playback tests
│   ├── test_fallbacks.py             # Frontend fallback tests
│   ├── test_simulation_state.py      # Simulation state management tests
│   └── test_multiplatform.py         # Multi-platform collector tests
├── data/                             # SQLite database (WAL mode)
│   ├── qvis.db
│   ├── qvis.db-shm
│   └── qvis.db-wal
├── scripts/
│   └── record_demo.py                # Demo recording guide script
├── docs/
│   ├── quantum-threat-taxonomy.md    # Q-ATT&CK v1.0 reference (581 lines)
│   └── defcon-demo-script.md         # DEF CON demo narration script
├── Dockerfile                        # Multi-stage Docker build (non-root user)
├── docker-compose.yml                # Production compose with security constraints
├── pyproject.toml                    # Poetry config (Python >=3.11)
├── requirements.txt                  # Pip requirements
├── pytest.ini                        # pytest configuration
├── .env.example                      # Environment variable template
├── .gitignore
├── LICENSE                           # MIT License
└── README.md                         # Project documentation
```

---

## 4. Backend Architecture (Python/FastAPI)

### 4.1 Data Models

**File**: `backend/threat_engine/models.py`

All data models use **Pydantic BaseModel** for automatic validation and serialization. This is the single source of truth for data shapes shared across the entire backend.

#### Severity Enum
```python
class Severity(str, Enum):
    critical = "critical"    # Red (#ff3333) — Immediate action required
    high     = "high"        # Orange (#ff8833) — Active threat
    medium   = "medium"      # Blue (#3388ff) — Suspicious activity
    low      = "low"         # Green (#22cc88) — Minor concern
    info     = "info"        # Steel (#88aacc) — Informational
```

#### Platform Enum
```python
class Platform(str, Enum):
    ibm_quantum    = "ibm_quantum"      # IBM Quantum (Qiskit Runtime)
    amazon_braket  = "amazon_braket"     # AWS Braket
    azure_quantum  = "azure_quantum"      # Azure Quantum
```

#### QubitCalibration
Represents calibration data for a single qubit:
- `qubit_id: int` — Qubit index
- `t1_us: float` — T1 relaxation time in microseconds
- `t2_us: float` — T2 dephasing time in microseconds
- `readout_error: float` — Readout error rate (0.0–1.0)
- `gate_error_cx: Optional[float]` — CNOT gate error rate

#### BackendNode
Represents a quantum computing backend:
- `id: str` — Unique backend identifier (e.g., `"ibm_sherbrooke"`)
- `name: str` — Display name
- `platform: Platform` — Cloud platform enum
- `num_qubits: int` — Number of qubits
- `is_simulator: bool` — Whether it's a simulator (no real hardware)
- `operational: bool` — Currently accepting jobs
- `calibration: List[QubitCalibration]` — Per-qubit calibration data
- `api_surface_score: float` — Attack surface score (0.0–1.0)
- `threat_level: Severity` — Current threat assessment
- `position_hint: Optional[Tuple[float, float, float]]` — 3D position (set by frontend)

#### ThreatEvent
The core threat detection output:
- `id: str` — UUID4 unique identifier
- `technique_id: str` — Q-ATT&CK technique ID (e.g., `"QTT007"`)
- `technique_name: str` — Human-readable technique name
- `severity: Severity` — Threat severity level
- `platform: Platform` — Target platform
- `backend_id: Optional[str]` — Target backend (if applicable)
- `title: str` — Short title
- `description: str` — Detailed description
- `evidence: dict` — Structured evidence dict (MUST contain `rule_name` and `threshold_used` per G6 quality gate)
- `detected_at: datetime` — UTC timestamp of detection
- `visual_effect: str` — Frontend visual effect type identifier
- `visual_intensity: float` — Visual intensity (0.0–1.0)
- `remediation: List[str]` — Recommended remediation steps

#### SimulationSnapshot
The top-level telemetry envelope:
- `snapshot_id: str` — UUID4 for this snapshot
- `generated_at: datetime` — Collection timestamp
- `backends: List[BackendNode]` — All tracked backends
- `threats: List[ThreatEvent]` — Active threats
- `entanglement_pairs: List[Tuple[str, str]]` — Backend pairs with quantum entanglement
- `total_qubits: int` — Sum of all backend qubits
- `total_threats: int` — Count of active threats
- `threats_by_severity: Dict[str, int]` — Severity distribution
- `platform_health: Dict[str, float]` — Per-platform health score (0.0–1.0)
- `model_config: {"extra": "allow"}` — Allows extra fields (raw telemetry data mixed in by collectors)

**How models relate**: `SimulationSnapshot` contains lists of `BackendNode` and `ThreatEvent`. Each `BackendNode` contains `QubitCalibration` objects. `ThreatEvent` references `Platform` and `Severity` enums. The `analyzer.py` orchestrator consumes `SimulationSnapshot` from collectors and produces enriched `ThreatEvent` lists via the detection rules.

---

### 4.2 Threat Engine

The threat engine is located in `backend/threat_engine/` and consists of five components: models, rules, baseline, correlator, and analyzer.

#### Module Dependency Graph
```
models.py ← rules.py ← analyzer.py → correlator.py
                ↑               ↓
                └─── baseline.py (independent, used by main.py directly)
```

- `models.py` — No internal dependencies; defines all data shapes
- `rules.py` — Imports only from `models.py`; defines detection rules and `ThresholdConfig`
- `baseline.py` — No internal imports; pure math (EMA + z-score)
- `correlator.py` — Imports from `models.py`; pattern matching on threat events
- `analyzer.py` — Imports from `models.py`, `rules.py`, and `storage.database`; orchestrates the pipeline

---

### 4.3 Detection Rules

**File**: `backend/threat_engine/rules.py` (482 lines)

#### Architecture: Pure Functions + Centralized Configuration

Every detection rule follows the signature:
```python
def RULE_XXX_name(data: Dict[str, Any]) -> List[ThreatEvent]:
```

Rules are **pure functions** — they receive a raw dictionary and return a list of `ThreatEvent` objects. They never access global mutable state (except via the `_cfg()` helper for threshold configuration).

#### ThresholdConfig Dataclass

```python
@dataclass
class ThresholdConfig:
    rule_002_calibration_harvest_ratio: Optional[float] = None   # Default: 3.0
    rule_003_identity_gate_ratio: Optional[float] = None           # Default: 0.7
    rule_003_max_circuit_gates: Optional[int] = None                # Default: 20
    rule_004_max_failed_attempts: Optional[int] = None              # Default: 5
    rule_005_max_depth_ratio: Optional[float] = None                # Default: 0.85
    rule_006_max_sequential_404: Optional[int] = None               # Default: 10
    rule_007_max_admin_403: Optional[int] = None                     # Default: 3
    rule_008_t1_baseline_ratio: Optional[float] = None               # Default: 0.6
    rule_009_min_backends_accessed: Optional[int] = None             # Default: 3
    rule_010_measure_ratio: Optional[float] = None                   # Default: 0.5
    rule_010_min_circuit_gates: Optional[int] = None                 # Default: 10
    enabled_rules: Optional[set] = None                              # None = all rules active
```

**Key design**: Any field left as `None` means "use the hardcoded default." This allows partial overrides — you can override some thresholds while letting others fall back to their conservative defaults.

#### _cfg() Helper

```python
def _cfg(attr_name: str, default: Any) -> Any:
```

Centralizes the `None`-guard logic. Rules call `_cfg('field_name', default)` instead of manually checking `_threshold_config is not None`. This eliminates a whole class of bugs where rules would crash if no config was installed.

#### Rule Registry and Enable/Disable

```python
ALL_RULES = [
    RULE_001_credential_leak_github_search,
    RULE_002_calibration_harvest_rate,
    RULE_003_timing_oracle_job_pattern,
    RULE_004_cross_tenant_id_probing,
    RULE_005_resource_exhaustion_circuit,
    RULE_006_ip_extraction_idor,
    RULE_007_token_scope_violation,
    RULE_008_backend_health_anomaly,
    RULE_009_concurrent_multi_backend_probing,
    RULE_010_anomalous_circuit_composition,
]

def get_active_rules() -> list:
    if _threshold_config is not None and _threshold_config.enabled_rules is not None:
        return [r for r in ALL_RULES if r.__name__ in _threshold_config.enabled_rules]
    return list(ALL_RULES)
```

Rules can be individually enabled/disabled by name via the `enabled_rules` set in `ThresholdConfig`.

#### Complete Rule Reference

| Rule | Q-ATT&CK ID | Technique Name | Severity | Threshold | Visual Effect | Input Key |
|------|-------------|---------------|----------|-----------|---------------|-----------|
| RULE_001 | QTT007 | Credential Exposure | Critical | N/A (any match) | `particle_leak` | `github_search_results` |
| RULE_002 | QTT002 | Calibration Harvesting | Medium | ratio > 3.0 | `calibration_drain` | `api_access_log.calibration_requests_last_hour` / `job_submissions_last_hour` |
| RULE_003 | QTT003 | Timing Oracle | High | identity_ratio > 0.7 AND total_gates < 20 | `timing_ring` | `recent_jobs[].gate_histogram` |
| RULE_004 | QTT004 | Tenant Probing | High | failed_attempts > 5 | `color_bleed` | `failed_job_access_attempts` |
| RULE_005 | QTT008 | Resource Exhaustion | Medium | depth/max_depth > 0.85 | `interference` | `recent_jobs[].depth` / `max_allowed_depth` |
| RULE_006 | QTT006 | IP Extraction/IDOR | Critical | sequential_404_count > 10 | `vortex` | `api_error_log.sequential_404_count` |
| RULE_007 | QTT005 | Scope Violation | High | 403_on_admin_count > 3 | `interference` | `api_error_log.403_on_admin_count` |
| RULE_008 | QTT010 | Hardware Degradation | Info | current_t1 < baseline_t1 * 0.6 | `calibration_drain` | `baseline_calibration` / `calibration[]` |
| RULE_009 | QTT001 | Multi-Backend Recon | High | backends_accessed >= 3 | `color_bleed` | `recent_jobs[].backend_id` |
| RULE_010 | QTT009 | Anomalous Circuit | Medium | measure_ratio > 0.5 AND total > 10 | `interference` | `recent_jobs[].gate_histogram` |

#### G6 Quality Gate: Evidence Schema

Every triggered `ThreatEvent` **MUST** include these fields in its `evidence` dict:
- `rule_name: str` — The exact Python function name that produced this event (e.g., `"RULE_002_calibration_harvest_rate"`)
- `threshold_used: Any` — The threshold value that was actually used (either from config or default)

This ensures full auditability: given any threat event in the database, you can trace exactly which rule produced it and what threshold it used at the time of detection.

#### Calibration Loading

On startup, `main.py` calls `load_threshold_config_from_file()` which reads `calibration_results.json` and builds a `ThresholdConfig`. The `calibrator.py` module produces this file by running the live IBM collector for a configurable duration, recording all observable metrics, and computing p95-based recommended thresholds.

---

### 4.4 Baseline & Anomaly Detection

**File**: `backend/threat_engine/baseline.py` (74 lines)

#### MetricBaseline

Tracks an exponential moving average (EMA) and variance for a single metric:

```python
@dataclass
class MetricBaseline:
    ema: float = 0.0              # Current EMA estimate
    ema_variance: float = 0.0     # Current EMA variance estimate
    count: int = 0                # Number of samples seen
    alpha: float = 0.1            # Smoothing factor (higher = more responsive)
    variance_floor_factor: float = 0.001  # 0.1% of ema^2 minimum variance
```

**EMA update formula**:
```
EMA_new = EMA_old + alpha * (value - EMA_old)
Var_new = (1 - alpha) * (Var_old + alpha * (value - EMA_old)^2)
```

**Variance floor**: The `variance_floor_factor` prevents false positives during warmup. When the first few samples are identical, variance is ~0, and a tiny deviation produces an enormous z-score (e.g., 33-sigma for 1% drift). The floor enforces a minimum variance of `factor * ema^2`, so the z-score is bounded:

```
effective_variance = max(ema_variance, variance_floor_factor * |ema|^2)
z_score = (value - ema) / sqrt(effective_variance)
```

**The floor is configurable** — both at construction time and at the `BaselineManager` level, allowing operators to tune sensitivity per deployment.

#### BaselineManager

Manages per-backend, per-metric baselines using a `defaultdict(MetricBaseline)`:

```python
class BaselineManager:
    def __init__(self, z_threshold: float = 2.5, variance_floor_factor: float = 0.001):
        ...
    def check(self, backend_id: str, metric_name: str, value: float) -> Optional[float]:
        ...
```

**Key behaviors**:
- **Warmup period**: First 3 samples (count <= 3) never trigger an alert, regardless of magnitude. This reduces the detection blind spot to ~90 seconds (at 30s interval).
- **Key format**: `"backend_id:metric_name"` (e.g., `"ibm_sherbrooke:q0_t1"`)
- **Z-score threshold**: Default 2.5 (|z| > 2.5 triggers). Configurable per manager instance.
- **Automatic propagation**: The manager ensures each baseline's `variance_floor_factor` matches its own, even for baselines created by the `defaultdict` before the manager's factor was set.

**How main.py uses it**: In the `simulation_loop()`, for each backend's calibration data, it calls `baseline_manager.check(backend.id, f"q{cal.qubit_id}_t1", cal.t1_us)` and `...t2...`. If the z-score exceeds the threshold, it creates a `ThreatEvent` with technique_id `"QTT014"` (Adaptive Baseline Anomaly). Severity scales with z-score magnitude: >4.0 = high, otherwise medium.

---

### 4.5 Cross-Rule Correlation

**File**: `backend/threat_engine/correlator.py` (188 lines)

#### CORRELATION_PATTERNS

Four predefined campaign patterns detect coordinated multi-stage attacks:

| Pattern Name | Technique Pair | Window | Escalated Severity | Description |
|---|---|---|---|---|
| Coordinated Reconnaissance | QTT003 + QTT002 | 30 min | Critical | Timing oracle + calibration harvest = QPU characterization campaign |
| Pre-Attack Staging | QTT007 + QTT003 | 60 min | Critical | Credential exposure + timing probes = active exploitation with leaked creds |
| Enumeration Campaign | QTT004 + QTT006 | 15 min | Critical | Tenant probing + IDOR = unauthorized access campaign |
| Resource Abuse Chain | QTT008 + QTT005 | 30 min | High | Resource exhaustion + privilege escalation |

#### ThreatCorrelator

```python
class ThreatCorrelator:
    def __init__(self, history_hours: float = 2.0, max_history: int = 500):
        ...
    def correlate(self, new_threats: List[ThreatEvent]) -> List[ThreatEvent]:
        ...
    def reset(self):
        ...
```

**How correlation works**:

1. **History tracking**: All threat events are stored in `recent_threats` (capped at `max_history` entries). Old events are pruned based on `history_hours`.

2. **Pattern matching**: For each correlation pattern, the correlator checks if **both** required technique IDs appear on the **same backend** within the pattern's time window.

3. **Quick optimization**: Before doing per-backend work, it checks if any of the new threats' technique IDs intersect the pattern's required techniques. If not, the pattern is skipped entirely (O(1) check).

4. **Deduplication**: Campaign events are deduplicated using `CORR:{backend_id}:{pattern_name}` keys stored in `_campaign_dedup`. This set is independent from `recent_threats` so that pruning old events doesn't allow the same campaign to re-fire.

5. **Campaign expiry**: Dedup keys expire when none of the underlying technique IDs for that pattern exist in `recent_threats` anymore.

6. **Auto-correction**: If `history_hours` is shorter than the longest correlation window (60 min = 1 hour), it's automatically corrected upward with a warning log.

7. **Evidence structure**: Campaign events include `pattern_name`, `techniques_found`, `backend_id`, `window_minutes`, and `triggering_threats` (list of {id, technique, severity}).

**Campaign events** are emitted with:
- `visual_effect = "campaign"` — Red lightning arcs radiating outward (frontend)
- `visual_intensity = 0.9` — Maximum intensity
- Generic remediation for coordinated campaign investigation

---

### 4.6 Threat Analyzer (Orchestrator)

**File**: `backend/threat_engine/analyzer.py` (148 lines)

```python
class ThreatAnalyzer:
    def __init__(self):
        self.active_threats: Dict[tuple, ThreatEvent] = {}  # (backend_id, technique_id) -> event
        self._persisted_ids: Set[str] = set()               # Already in SQLite
```

#### analyze() Method

The core orchestration method that the simulation loop calls every cycle:

1. **Rule execution**: Iterates `get_active_rules()` (respects `enabled_rules` filter) and calls each rule with the raw snapshot data
2. **Threat deduplication**: Uses `(backend_id, technique_id)` as a key. If the same key already exists:
   - Within 5 minutes: Keeps the original event ID (UI continuity) but updates the event data and marks it for re-persistence
   - After 5 minutes: Treats as a new occurrence
3. **Severity sorting**: All active threats are sorted by severity rank (critical=0, high=1, medium=2, low=3, info=4)
4. **Snapshot enrichment**: In non-dict mode, merges new threats into the snapshot, updates counts and severity distribution
5. **Dual mode**: Accepts either `SimulationSnapshot` (for real pipeline) or raw `dict` (for testing)

#### persist_new_threats() / resolve_disappeared_threats()

These async methods handle SQLite persistence:
- **persist_new_threats()**: Scans `active_threats`, INSERT OR REPLACE any event not in `_persisted_ids`. Uses lazy import of `save_threat` to avoid circular imports.
- **resolve_disappeared_threats()**: Scans `_persisted_ids` for IDs no longer in `active_threats`, sets `resolved_at` timestamp in the database.
- Both methods are resilient: exceptions are logged as warnings but never crash the analysis loop.

**How main.py uses the analyzer**: The `simulation_loop()` calls `analyzer.analyze(snapshot)`, then separately handles baseline checks and correlation. Campaign events from the correlator are added to `analyzer.active_threats` directly (so they participate in persistence). Finally, `persist_new_threats()` and `resolve_disappeared_threats()` are called.

---

### 4.7 Collectors Layer

**Directory**: `backend/collectors/`

#### BaseCollector (Abstract)
```python
class BaseCollector(ABC):
    @abstractmethod
    async def collect(self) -> SimulationSnapshot:
        pass
```

The Strategy pattern: all collectors implement the same interface, making them interchangeable.

#### Collector Strategy Selection (in main.py)

The collector is chosen at startup based on environment:
1. **Test mode** (`PYTEST_CURRENT_TEST` or `USE_MOCK=true`): `MockCollector` with deterministic mode
2. **Demo mode** (`settings.demo_mode=True`): `AggregatorCollector` wrapping mock IBM + Braket + Azure
3. **Production** (IBM token present): `IBMQuantumCollector` (optionally + Braket + Azure via `AggregatorCollector`)
4. **Fallback** (no tokens): `MockCollector` with a warning log

#### MockCollector

Returns pre-populated data for 4 IBM backends (ibm_sherbrooke, ibm_kyoto, ibm_brisbane, ibm_qasm_simulator) with 4 seed threats (credential exposure, timing oracle, calibration harvesting, resource exhaustion). In non-test mode, applies random variations to calibration T1 values and API surface scores, and randomly adds/removes threats (20% chance per cycle).

#### IBMQuantumCollector

Live collector using `qiskit_ibm_runtime.QiskitRuntimeService`:
- Fetches all available backends with status, configuration, properties
- Extracts per-qubit T1, T2, readout_error, and CNOT gate errors
- Retrieves recent job history (last 10 jobs) with circuit depth and gate histograms
- Computes API surface score based on qubit count and simulator status
- Determines threat level based on T1 (< 30us = high, < 60us = medium)
- **Degraded mode**: On auth failure or collection error, returns a cached snapshot with `degraded: True` metadata
- **Data validation**: Rejects implausible coherence values (>10s), handles missing properties gracefully

#### BraketCollector

Live collector using `boto3` for AWS Braket:
- Searches for QPU devices via `search_devices` API
- Fetches device capabilities to extract qubit counts and fidelity data
- Derives `readout_error = 1.0 - fidelity` from one-qubit fidelity specs
- Sets conservative default T1/T2 placeholders (since Braket doesn't expose them)
- Limits calibration data to first 5 qubits for performance
- Falls back to mock on ImportError or API errors

#### AzureQuantumCollector

Live collector using `azure.quantum.Workspace`:
- Lists workspace targets (IonQ Aria, Quantinuum H1, Rigetti)
- Uses a hardcoded qubit map for known Azure Quantum targets
- Falls back to mock on missing credentials or ImportError

#### AggregatorCollector

Runs multiple collectors in parallel via `asyncio.gather()`:
```python
tasks = [c.collect() for c in self.collectors]
results = await asyncio.gather(*tasks, return_exceptions=True)
```
Merges all backends, threats, entanglement pairs, and platform health scores into a single `SimulationSnapshot`. Sub-collector exceptions are logged but don't crash the aggregation.

#### GitHubTokenScanner

Separate from the collector pipeline — called directly by `main.py` every 5 minutes:
- Uses GitHub Code Search API (`/search/code`) with the query `"QiskitRuntimeService+token+"`
- Extracts match text from `text_matches` fragments
- Returns a list of `{repo, file, pattern, url}` dicts
- Handles rate limiting (403) and auth errors (401) gracefully
- Results are injected into RULE_001's raw data input by the simulation loop

#### ThresholdCalibrator

Offline CLI tool for learning empirical thresholds from live data:
- Runs the IBM collector for a configurable duration (default 60 minutes)
- Records every observable metric: calibration harvest ratios, identity gate ratios, circuit sizes, depth ratios, measure ratios, T1 values, backend counts
- Computes per-metric p95 (or p5 for floor-type metrics) thresholds
- Saves results to `calibration_results.json`
- Invoked via `python -m backend.main --calibrate [duration_minutes]`

#### ScenarioCollector

Pre-recorded attack sequence playback for demonstrations:
- **recon**: Calibration harvest → Timing oracle → Coordinated Reconnaissance campaign
- **credential_exploit**: Credential exposure → Timing oracle → Pre-Attack Staging campaign
- **ddos_circuit**: Resource exhaustion escalation → Resource Abuse Chain campaign
- Each scenario is a list of 4 snapshot dicts, played sequentially and looping
- Loaded/reset via `/api/scenario/load` and `/api/scenario/reset` endpoints

---

### 4.8 API Layer

**Directory**: `backend/api/`

#### REST Endpoints (main.py)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/health` | GET | No | Health check with platform info |
| `/api/snapshot` | GET | Optional | Current `SimulationSnapshot` |
| `/api/backends` | GET | Optional | All backend nodes |
| `/api/threats` | GET | Optional | Active threats (filterable by severity) |
| `/api/threat/{threat_id}` | GET | Optional | Single threat detail (input-validated) |
| `/api/threats/export/stix` | GET | Optional | STIX 2.1 Bundle (paginated) |
| `/api/threats/history` | GET | Optional | Paginated history from SQLite |
| `/api/threats/stats` | GET | Optional | Aggregated statistics |
| `/api/scenario/load` | POST | Optional | Load attack scenario |
| `/api/scenario/list` | GET | No | List available scenarios |
| `/api/scenario/reset` | POST | Optional | Reset to default collector |
| `/ws/simulation` | WebSocket | Optional | Live telemetry stream |

#### Authentication (auth.py)

- API key via `X-API-Key` header
- Keys are SHA-256 hashed for storage and comparison
- Constant-time comparison via `secrets.compare_digest()` to prevent timing attacks
- Authentication is optional: when `AUTH_ENABLED=false`, all endpoints are open
- WebSocket auth via query parameter: `ws://host/ws/simulation?token=<key>`

#### WebSocket (websocket.py)

```python
class ConnectionManager:
    MAX_CONNECTIONS = 200
    MAX_MESSAGE_SIZE = 256 * 1024   # 256 KB
    MAX_MESSAGES_PER_MINUTE = 60
```

- Connection limit of 200 concurrent WebSocket clients
- Per-client message rate limiting (60 msg/min, sliding window)
- Message size validation (256 KB max)
- Automatic disconnect on error with cleanup of rate tracking
- `broadcast_snapshot()` serializes via `model_dump_json()`

#### Rate Limiting (ratelimit.py)

Weighted sliding-window rate limiter for API routes:
- Parses `RATE_LIMIT` setting in `"requests/seconds"` format (default: `"60/60"`)
- Tracks per-IP request counts in time windows
- Weighted calculation: `estimated = prev_count * (1 - window_position) + curr_count`
- Memory pruning: caps tracked IPs at 10,000, evicts stale entries every 100 requests
- IP validation: rejects control characters, null bytes, path separators
- Returns `429 Too Many Requests` with `Retry-After` header when exceeded
- Adds `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers to all API responses

#### Security Headers (security_headers.py)

Applied to every HTTP response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy`: Strict CSP with whitelisted CDN origins, `unsafe-inline` for Three.js shaders, `blob:` for Swagger workers, `connect-src` allows `ws:` and `wss:`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (1 year)
- `Cache-Control: no-store` for all `/api/*` responses

#### STIX Export (export.py)

Converts threat events to STIX 2.1 Indicator objects:
- Maps severity to confidence scores (critical=95, high=80, medium=60, low=40, info=20)
- Uses UUID5 (namespace-based) for deterministic STIX IDs
- LRU cache (5,000 entries) for STIX ID mapping
- Bundle includes pagination metadata and QVis-specific extensions (`x-qvis-threat`)
- Content-hash-based bundle ID for deduplication

#### Request ID Middleware

Adds `X-Request-ID` header to every response:
- Accepts client-provided `X-Request-ID` or generates a UUID4 (first 8 chars)
- Binds request ID to structlog context for correlated log tracing
- Clears context vars between requests to prevent leak

#### Path Traversal Protection

The `serve_frontend()` catch-all route:
- Blocks null bytes (`\x00`, `%00`) in path
- Blocks `..` in both raw and URL-decoded forms
- Rejects reserved paths (`docs`, `redoc`, `openapi.json`)
- Validates path length
- SPA fallback: serves `index.html` for any unmatched route

---

### 4.9 Storage Layer

**File**: `backend/storage/database.py` (391 lines)

#### SQLite with WAL Mode

```python
await _connection.execute("PRAGMA journal_mode=WAL;")
await _connection.execute("PRAGMA synchronous=NORMAL;")
```

- **WAL mode**: Readers never block writers and vice-versa — critical for concurrent WebSocket broadcasting + API reads
- **Normal synchronous**: Balances durability and performance
- **Shared connection**: Single `aiosqlite.Connection` with lazy initialization and asyncio lock

#### Tables

**threat_events** (14 columns):
- `id TEXT PRIMARY KEY`
- `technique_id, severity, platform, backend_id, title, description` — Core event fields
- `evidence TEXT (JSON)` — Serialized evidence dict
- `detected_at TEXT (ISO-8601)` — Detection timestamp
- `visual_effect, visual_intensity` — Frontend rendering data
- `remediation TEXT (JSON)` — Recommended actions
- `resolved_at TEXT (ISO-8601, nullable)` — Resolution timestamp (NULL while active)

**Indexes**: `detected_at`, `severity`, `technique_id`, `backend_id`, `resolved_at`

**correlation_events** (7 columns):
- `id TEXT PRIMARY KEY`
- `pattern_name TEXT` — e.g., "Coordinated Reconnaissance"
- `techniques TEXT (JSON)` — List of technique IDs
- `backends TEXT (JSON)` — List of backend IDs
- `detected_at TEXT (ISO-8601)`
- `severity TEXT`

#### CRUD Operations

- `save_threat()`: INSERT OR REPLACE (idempotent upsert)
- `get_threats()`: Paginated query with optional severity filter, newest first
- `get_threat_by_id()`: Single lookup by primary key
- `resolve_threat()`: Sets `resolved_at` to now (returns True if row updated)
- `save_correlation()`: INSERT OR REPLACE for campaign events
- `get_correlations()`: Paginated correlation history
- `get_threat_stats()`: Aggregated statistics (total, by_severity, by_platform, by_technique, first/last detected)

---

### 4.10 Configuration

**File**: `backend/config.py` (43 lines)

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="forbid")
```

Uses `pydantic-settings` with `.env` file support. Key settings:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `demo_mode` | bool | True | Use mock data for multi-platform demo |
| `update_interval_seconds` | int | 30 | Simulation loop cycle time |
| `ibm_quantum_token` | SecretStr | "" | IBM Quantum API token |
| `aws_access_key_id` | SecretStr | "" | AWS access key |
| `aws_secret_access_key` | SecretStr | "" | AWS secret key |
| `aws_default_region` | str | "us-east-1" | AWS region |
| `azure_quantum_subscription_id` | SecretStr | "" | Azure subscription ID |
| `auth_enabled` | bool | False | Enable API key authentication |
| `api_key` | SecretStr | "" | API key for authentication |
| `rate_limit` | str | "60/60" | Rate limit (requests/seconds) |
| `log_level` | str | "INFO" | Logging level |
| `log_format` | str | "console" | "console" or "json" |
| `github_token` | SecretStr | "" | GitHub PAT for token scanning |
| `slack_webhook_url` | SecretStr | "" | Slack alerting webhook |
| `discord_webhook_url` | SecretStr | "" | Discord alerting webhook |

`SecretStr` fields are never exposed via `repr()` or logging. The `extra="forbid"` setting prevents typos in env vars from being silently ignored.

---

## 5. Frontend Architecture (Vanilla JS + Three.js)

The frontend is a **single-page application** (SPA) with no build step, no framework, and no bundler. All JavaScript is loaded as ES modules from the HTML file. Three.js r128 is loaded from CDN with graceful degradation.

### 5.1 Application Bootstrap

**File**: `frontend/js/main.js` (700 lines)

The bootstrap sequence runs in 5 stages:

```
Stage 1: FallbackManager.detectCapabilities()
         ↓
Stage 2: FallbackManager.validateCriticalScripts()
         ↓
Stage 3: initThreeJS() OR initCanvas2D()
         ↓
Stage 4: initWebSocket()
         ↓
Stage 5: initKeyboardShortcuts()
```

**Stage 3 (Three.js init)** creates the full 3D scene:
- Dark background (`0x020408`) with exponential fog
- Perspective camera at z=600
- WebGL renderer with Reinhard tone mapping and antialiasing
- Optional UnrealBloomPass for glow effects (gracefully disabled if unavailable)
- 3 point lights (key, fill, rim)
- Grid helper on the XZ plane
- Star field (3000 particles via custom GLSL shader with twinkling)
- Instantiates: `ParticleSystem`, `ThreatVisualManager`, `EntanglementRenderer`, `Controls`, `StateMapper`, `HUD`, `ThreatPanel`, `Legend`, `Timeline`

**Render loop** (`animateWebGL`):
- Updates TWEEN animations
- Updates all Backend instances (rotation, glow pulsing)
- Updates ParticleSystem (orbital motion, threat effects)
- Updates ThreatVisualManager (effect animations)
- Updates EntanglementRenderer (traveling particles)
- Feeds PerformanceMonitor (FPS counter)

**Keyboard shortcuts** (20+ shortcuts):
- `ESC`: Close panel / reset camera
- `R`: Reset camera to origin
- `Space`: Toggle idle rotation
- `+/-`: Zoom in/out
- `Ctrl+F`: Toggle FPS counter
- `Ctrl+D`: Toggle diagnostics
- `H`: Toggle HUD
- `M`: Mute/unmute audio
- `?`: Show help overlay

### 5.2 Data Pipeline

#### WSClient (`frontend/js/data/WSClient.js`, 320 lines)

Production-grade WebSocket client:
- **Reconnection**: Exponential backoff from 1s to 30s with ±25% jitter, max 50 attempts
- **Heartbeat**: Sends `{"type":"ping"}` every 30 seconds, 10s timeout
- **Quality metrics**: Tracks messages received, rolling messages/sec, uptime, disconnects
- **State machine**: `IDLE → CONNECTING → CONNECTED → RECONNECTING → OFFLINE/CLOSED`
- **DOM integration**: Updates `#connection-status` pill with appropriate styling
- **Event dispatching**: Fires `wsStateChange` custom events for toast notifications
- **Offline resilience**: Caches last snapshot via `FallbackManager`, supports queued callbacks for post-reconnection execution

#### StateMapper (`frontend/js/data/StateMapper.js`, 287 lines)

The critical glue between data and visuals:

1. **Backend diffing**: Compares snapshot backend list with existing 3D nodes. Creates new `Backend` instances, removes stale ones.
2. **Threat effect mapping**: Iterates snapshot threats, calls `ParticleSystem.triggerThreatEffect()` and `ThreatVisualManager.applyThreatEffect()` for each. Clears effects for backends without active threats.
3. **Entanglement diffing**: Maintains `previousEntanglements` set, adds/removes tubes based on snapshot diff.
4. **HUD update**: Calls `hud.update(snapshot)` to refresh stats, status, and ticker.
5. **Raycasting**: Sets up `THREE.Raycaster` on canvas click. Hit detection uses backend `core` mesh geometry. On hit: flies camera to backend, opens threat panel, shows detail overlay.

#### appState (`frontend/js/state.js`, 5 lines)

Minimal shared mutable state:
```javascript
const appState = {
    camera: null,           // Set by main.js
    controls: null,         // Set by main.js
    isAnimatingCamera: false // Set/read by StateMapper and main.js
};
```

### 5.3 3D Simulation Layer

#### Backend (`frontend/js/simulation/Backend.js`, 142 lines)

Each quantum backend is a Three.js scene graph group:

- **Core sphere**: `MeshPhongMaterial` with platform-specific color and emissive glow
  - IBM Quantum: `0x2255bb` (blue)
  - Amazon Braket: `0x8844ff` (purple)
  - Azure Quantum: `0x44ff88` (green)
  - Simulator: Muted `0x335577`
- **Glow ring**: `TorusGeometry` at 1.4x core radius, semi-transparent, rotating
- **Orbit rings**: Two torus geometries at 2x and 2.8x radius, tilted at different angles, rotating
- **Text label**: Sprite with CanvasTexture rendering the backend name in 24px Share Tech Mono
- **Layout**: Deterministic circular layout — angle = `index / total * 2π`, radius = 150, Y staggered ±25

**Threat level coloring**: Modifies emissive color/intensity of the core sphere:
- `none`: Base platform color, no emissive
- `low`: Green tint
- `medium`: Yellow tint
- `high`: Orange tint
- `critical`: Red glow (`0xaa1100`)

#### ParticleSystem (`frontend/js/simulation/ParticleSystem.js`, 172 lines)

GPU-accelerated orbital particle system using Three.js `BufferGeometry`:

- **Capacity**: 2000 particles maximum (pre-allocated Float32Array buffers)
- **Per-backend spawning**: `ceil(qubits / 4)` particles per backend (max 100)
- **Orbital motion**: Each particle has random orbit radius, speed, phase, inclination
- **Threat effects**: Seven visual behaviors triggered by threat type:
  - `particle_leak`: 30% chance particles fly outward and fade to red
  - `color_bleed`: 15% chance particles turn amber
  - `timing_ring`: Slow down orbit, orange tint
  - `calibration_drain`: Green tint
  - `vortex`: Spiral inward, reset when radius < 5
  - `interference`: Random positional jitter, white flashes
  - `campaign`: (handled by ThreatVisuals, not particles)
- **Buffer updates**: Marks `position.needsUpdate` and `color.needsUpdate` per frame

#### EntanglementRenderer (`frontend/js/simulation/Entanglement.js`, 104 lines)

Renders quantum entanglement as glowing tube connections:

- **Curve**: `CatmullRomCurve3` with 5 control points arcing upward between two backends
- **Tube**: `TubeGeometry` with additive-blended teal material
- **Particles**: 3-6 small spheres that travel along the curve (animated per frame)
- **Animation**: Scale pulsing (sin wave) and opacity fading
- **Deduplication**: Uses canonical sorted key `"idA-idB"` to prevent duplicate tubes

#### ThreatVisualManager (`frontend/js/simulation/ThreatVisuals.js`, 274 lines)

Seven distinct 3D visual effects triggered by threat events:

1. **timing_ring**: Expanding orange ring (`RingGeometry`), scales up and fades out
2. **calibration_drain**: Green wireframe cone (funnel shape), rotates around backend
3. **vortex**: Dark sphere + red rotating disc (fixed position)
4. **particle_leak**: Pulsing red sphere offset from backend center
5. **interference**: Random white line segments scattered in 3D space around backend
6. **color_bleed**: Large semi-transparent amber halo sphere with breathing scale animation
7. **campaign**: Multiple red lightning arcs (`QuadraticBezierCurve3` → `TubeGeometry`) radiating outward with glowing tips, plus core pulse sphere. Arc count scales with `triggering_threats` count from evidence.

All effects are keyed by `backend.id` in `activeEffects` Map and properly disposed when cleared.

### 5.4 UI Components

#### HUD (`frontend/js/ui/HUD.js`, 195 lines)

Fixed-position overlay showing:
- **Title bar**: "QVIS — QUANTUM THREAT TOPOLOGY ENGINE" + status pills + FPS toggle
- **Stats grid**: Critical (with flash-red animation on increase), High, Medium, Backend count, Qubit count
- **Meta info**: Collection time, connection info, collection source
- **Threat ticker**: Horizontally scrollable bar showing latest threat titles (clickable → opens ThreatPanel)
- **Footer**: Keyboard shortcut hints
- **Status pills**: Live (green), DEMO (amber), DEGRADED (orange), Disconnected (red), Connecting (yellow), Reconnecting (flashing yellow), Offline (gray)

#### Controls (`frontend/js/ui/Controls.js`, 187 lines)

Custom spherical coordinate camera orbit controller:
- **Input**: Mouse drag, scroll wheel, touch (single-finger drag + two-finger pinch zoom)
- **Coordinates**: `radius` (distance), `theta` (horizontal angle), `phi` (vertical angle)
- **Idle rotation**: Auto-rotates after 10 seconds of inactivity (respects `prefers-reduced-motion`)
- **Damping**: Smooth 0.05 lerp factor for all camera movements
- **Limits**: Zoom 100–2000, phi clamped to 0.1–π-0.1
- **Interruption**: `isAnimatingCamera` flag pauses orbit during TWEEN fly-to animations

#### ThreatPanel (`frontend/js/ui/ThreatPanel.js`, 324 lines)

Right-side slide-in detail panel with two views:

**Backend View**: Platform badge, meta grid (qubits, status, type, threat level), clickable threat card list with empty state handling.

**Threat Detail View**: Technique badge, severity label, title, description, evidence box (key-value pairs), remediation checklist (interactive checkboxes), "COPY REPORT JSON" button (Clipboard API + textarea fallback), "MARK REMEDIATED" button.

All text is HTML-escaped (XSS prevention). Transitions via CSS `transform: translateX()` with cubic-bezier easing.

#### Timeline (`frontend/js/ui/Timeline.js`, 280 lines)

Fixed bottom bar showing chronological threat events:
- Fetches history from `/api/threats/history` REST API
- Subscribes to `snapshotUpdate` events for live updates
- Renders colored dots (severity-colored, 10px circles with connecting lines)
- Hover tooltip shows severity badge, title, backend, technique, timestamp
- Deduplicates by `threat.id` using `_knownIds` Set

#### Legend (`frontend/js/ui/Legend.js`, 101 lines)

Bottom-left panel showing:
- **Platforms**: Dynamically filtered to show only platforms with active backends
- **Threat Visuals**: 6 static entries (Timing Oracle ◎, Credential Leak ▲, Calibration Harvest ▼, Interference ≈, IP Extraction ●, Campaign ⚡)

### 5.5 Core Infrastructure

#### FallbackManager (`frontend/js/core/FallbackManager.js`, 212 lines)

Central capability detection and error boundary:

- **Capability detection**: WebGL (1/2), Canvas 2D, WebSocket, Performance API, TypedArrays, ES6 Modules, SharedArrayBuffer, requestAnimationFrame, Clipboard API, Touch, GPU renderer name
- **Script validation**: Checks `THREE` global and core classes; detects optional deps (EffectComposer, TWEEN)
- **State machine**: `NOMINAL` (full WebGL) → `FALLBACK_2D` (Canvas 2D) → `CRITICAL` (error screen)
- **Offline caching**: Stores last WebSocket snapshot for offline rendering
- **Global error handlers**: Catches `window.error`, `unhandledrejection`, `online`/`offline` events
- **Diagnostic report**: GPU renderer, connection type, device memory, CPU cores, screen resolution, pixel ratio

#### AudioEngine (`frontend/js/core/AudioEngine.js`, 211 lines)

Procedural Web Audio API sound engine (no audio files):
- **Ambient hum**: Low A drone (55Hz sine) with LFO modulation (0.3Hz, ±5Hz)
- **Alert sound**: Critical threat — two-tone descending sine (880→440Hz, then 660→330Hz)
- **Connect sound**: High threat — ascending sine (220→880Hz)
- **Click sound**: UI interaction — short square wave (1200→600Hz, 50ms)
- **Persistence**: Enabled state saved to `localStorage` (`qvis-audio-enabled`)
- **Autoplay policy**: Init deferred to first user interaction

#### PerformanceMonitor (`frontend/js/core/PerformanceMonitor.js`, 171 lines)

Real-time FPS overlay:
- Rolling average over 60 samples
- Color-coded: green (≥50 FPS), yellow (≥30), red (<30)
- Reads `renderer.info.render.calls` and `triangles` from WebGL renderer
- Chrome-only heap memory display via `performance.memory`
- Toggle via Ctrl+F or HUD button

#### ToastManager (`frontend/js/core/ToastManager.js`, 115 lines)

Non-intrusive notification system:
- Four types: info (4s), warning (5s), error (7s), success (3s)
- Stacks up to 5, auto-dismisses
- ARIA `role="log"` and `aria-live="polite"` for accessibility
- Enter animation via `requestAnimationFrame` → `.toast-visible`
- Exit via `.toast-exit` + removal after 400ms

### 5.6 2D Fallback Renderer

**File**: `frontend/js/renderers/Canvas2DFallback.js` (318 lines)

Complete 2D canvas renderer for environments without WebGL:

- **Backend rendering**: Platform-colored radial gradient spheres with glow, orbit ring, orbital particle animation, name labels
- **Entanglement**: Quadratic bezier curves with traveling dot
- **Threat HUD**: Severity count overlay
- **Visual effects**: Fade trail (semi-transparent clear), grid, "2D FALLBACK MODE" watermark
- **Independent render loop**: Own `requestAnimationFrame` loop, receives snapshots directly (bypasses StateMapper)

### 5.7 CSS Theme

**File**: `frontend/css/main.css` (638 lines)

DEF CON presentation-ready dark theme:
- Background: `#020408` (near-black)
- Font: Share Tech Mono (monospace)
- **Vignette**: Radial gradient overlay + CSS scanline pseudo-element
- **Glassmorphism**: `backdrop-filter: blur(12px)` for panels
- **Severity colors**: Critical=#ff3333, High=#ff8833, Medium=#3388ff, Low=#22cc88, Info=#88aacc
- **Flash-red animation**: Critical count CSS keyframe on value increase
- **Responsive**: @media (max-width: 768px) hides non-essential elements

---

## 6. Data Flow & Event System

### WebSocket Message Protocol

Client → Server:
```json
{"type": "get_snapshot"}
{"type": "focus_backend", "backend_id": "ibm_sherbrooke"}
{"type": "ping"}
```

Server → Client:
```json
// Full SimulationSnapshot as JSON (every 30s by default)
{
  "snapshot_id": "uuid",
  "generated_at": "ISO-8601",
  "backends": [...],
  "threats": [...],
  "entanglement_pairs": [...],
  "total_qubits": 413,
  "total_threats": 4,
  "threats_by_severity": {...},
  "platform_health": {...}
}

// Acknowledgment messages
{"type": "backend_focus_ack", "backend": {...}}
```

### Custom DOM Event Bus

| Event | Dispatched By | Consumed By | Payload |
|---|---|---|---|
| `snapshotUpdate` | `main.js` (on WS message) | `Timeline`, `Legend` | `{snapshot}` |
| `wsStateChange` | `WSClient._setState()` | `main.js` (toast notifications) | `{oldState, newState, metrics, attempt}` |
| `openThreatPanel` | `StateMapper` (raycast hit), `HUD` (ticker click) | `ThreatPanel` | `{backend?, threat?}` |
| `backendSelected` | `StateMapper` (raycast hit) | `main.js` (detail overlay) | `{backend, threats}` |

---

## 7. Q-ATT&CK Threat Taxonomy

The Q-ATT&CK (Quantum Adversarial Tactics, Techniques, and Countermeasures Knowledge) framework maps quantum-specific attack vectors to 10 detection techniques:

| Technique ID | Rule | Name | MITRE ATT&CK Mapping | Default Threshold |
|---|---|---|---|---|
| QTT001 | RULE_009 | Multi-Backend Reconnaissance | TA0043 (Reconnaissance) | ≥ 3 backends |
| QTT002 | RULE_002 | Calibration Harvesting | TA0040 (Impact) | ratio > 3.0 |
| QTT003 | RULE_003 | Timing Oracle | TA0009 (Collection) | ratio > 0.7, gates < 20 |
| QTT004 | RULE_004 | Tenant Probing | TA0001 (Initial Access) | > 5 attempts |
| QTT005 | RULE_007 | Scope Violation | TA0003 (Persistence) | > 3 admin 403s |
| QTT006 | RULE_006 | IP Extraction/IDOR | TA0009 (Collection) | > 10 sequential 404s |
| QTT007 | RULE_001 | Credential Exposure | TA0006 (Credential Access) | Any match |
| QTT008 | RULE_005 | Resource Exhaustion | TA0040 (Impact) | depth_ratio > 0.85 |
| QTT009 | RULE_010 | Anomalous Circuit | TA0002 (Execution) | ratio > 0.5, gates > 10 |
| QTT010 | RULE_008 | Hardware Degradation | TA0040 (Impact) | T1 < baseline * 0.6 |

### Campaign Correlation Patterns

| Campaign | Techniques | Window | Escalated Severity | Real-World Analog |
|---|---|---|---|---|
| Coordinated Reconnaissance | QTT003 + QTT002 | 30 min | Critical | APT targeting QPU characterization |
| Pre-Attack Staging | QTT007 + QTT003 | 60 min | Critical | Credential theft → active exploitation |
| Enumeration Campaign | QTT004 + QTT006 | 15 min | Critical | Systematic tenant/job enumeration |
| Resource Abuse Chain | QTT008 + QTT005 | 30 min | High | DDoS via circuit depth abuse |

---

## 8. Security Hardening

### Backend Security

1. **Authentication**: Optional API key via `X-API-Key` header, SHA-256 hashed, constant-time comparison
2. **Rate Limiting**: Weighted sliding-window (default 60/60), IP validation, memory pruning (10k IP cap)
3. **Security Headers**: CSP, HSTS (1yr + subdomains), X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
4. **Path Traversal Protection**: Null byte blocking, `..` detection (raw + decoded), reserved path rejection
5. **Input Validation**: Threat ID regex validation, scenario name regex validation, path length limits
6. **WebSocket Hardening**: Connection limit (200), message size limit (256KB), per-client rate limiting (60/min)
7. **XSS Prevention**: HTML escaping in all user-facing output, CSP with `unsafe-inline` limited to CDN shaders
8. **SQL Injection Prevention**: Parameterized queries exclusively (aiosqlite `?` placeholders)
9. **Secret Management**: `SecretStr` for all credentials, redacted `__repr__`, no logging of secrets
10. **Container Security**: Non-root user (uid/gid 1000), read-only filesystem, no-new-privileges, tmpfs for /tmp

### Frontend Security

1. **XSS Prevention**: `sanitize()` utility for all innerHTML, `_escHtml()` in main.js overlay
2. **CSP Compliance**: Script loading only from whitelisted CDNs
3. **Content Security**: No eval() in application code, minimal `unsafe-inline` for Three.js
4. **Input Validation**: All data from WebSocket is consumed through Pydantic model validation on the backend

---

## 9. Deployment

### Docker

```dockerfile
# Multi-stage build
# Stage 1: Install Python dependencies
# Stage 2: Non-root runtime (uid/gid 1000)
# Port: 8000
# Entry: uvicorn backend.main:app
```

```yaml
# docker-compose.yml highlights
services:
  qvis:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,size=64m
    deploy:
      resources:
        limits: { cpus: '2.0', memory: 512M }
```

### Environment Configuration

All runtime configuration via `.env` file or environment variables. See `.env.example` for the complete list. Key variables:

```
DEMO_MODE=true
UPDATE_INTERVAL_SECONDS=30
IBM_QUANTUM_TOKEN=         # Required for live mode
AWS_ACCESS_KEY_ID=         # Optional: Braket
AZURE_QUANTUM_SUBSCRIPTION_ID=  # Optional: Azure
AUTH_ENABLED=false
API_KEY=
RATE_LIMIT=60/60
GITHUB_TOKEN=              # Optional: token scanning
```

### CLI: Calibration Mode

```bash
python -m backend.main --calibrate [duration_minutes]
```

Runs the live IBM collector for the given duration, computes p95-based thresholds, saves to `calibration_results.json`, and exits. The thresholds are automatically loaded on the next server startup.

---

## 10. Testing Strategy

### Test Suite: 322+ tests across 19 files

**Test organization**:
- `conftest.py`: Shared fixtures (backend builders, threat event builders, snapshot builder) + autouse fixtures that reset threshold config and rate limiter state between tests

**Core test coverage**:

| File | Tests | Coverage Area |
|---|---|---|
| `test_rules.py` | 80 | All 10 rules (positive/negative/edge), ThresholdConfig, evidence schema (G6), enabled_rules |
| `test_correlator.py` | 19 | 4 correlation patterns (positive/negative/missing), dedup, pruning, isolation, evidence structure |
| `test_baseline_manager.py` | 15 | EMA math, warmup, anomaly detection, gradual drift, edge cases, configurable variance floor |
| `test_threat_engine.py` | varies | Integration tests for full engine pipeline |
| `test_api.py` | varies | REST API endpoint tests |
| `test_e2e.py` | varies | End-to-end flow tests |
| `test_defcon_hardening.py` | varies | Security hardening validation |
| `test_scenario.py` | varies | Scenario playback tests |
| `test_collectors.py` | varies | Collector strategy tests |
| `test_github_scanner.py` | varies | GitHub token scanner tests |
| `test_fallbacks.py` | varies | Frontend fallback capability tests |
| `test_multiplatform.py` | varies | Multi-platform collector aggregation |

**Quality gates**:
- **G5**: All rules must use `_cfg()` for threshold access (no manual None checks)
- **G6**: All evidence dicts must contain `rule_name` and `threshold_used` fields
- **G7**: All Q-ATT&CK technique IDs must be within QTT001-QTT010 range

---

*This document was generated from exhaustive analysis of every source file in the QVis repository. Total: 30+ Python modules, 21 JavaScript modules, 19 test files, 638-line CSS stylesheet, and supporting infrastructure files.*
