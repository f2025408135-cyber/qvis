# QVis — Quantum Threat Topology Engine

<!-- Badges -->
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](https://github.com/f2025408135-cyber/qvis/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![DEFCON Ready](https://img.shields.io/badge/demo-DEFCON_ready-red.svg)](docs/defcon-demo-script.md)

```text
    ___ _    ___     
   / _ \ |  / (_)____
  / /_)/ | / / / ___/
 / ___/| |/ / (__  ) 
/_/    |___/_/____/  
```

QVis is a real-time visual threat intelligence platform for quantum cloud infrastructure. It takes abstract security telemetry from quantum platforms like IBM Quantum and renders the entire attack topology as a living 3D particle simulation in the browser. 

The entire field of quantum security risk communication is broken. Security findings are just abstract JSON that no CISO, executive, or policymaker can look at and intuitively grasp. QVis makes quantum cloud attack surfaces visceral and immediately communicable to any audience.

## Features

| Capability | Description |
|---|---|
| **Real-time 3D Visualization** | Three.js particle simulation rendering backend topology, threat events, and entanglement relationships |
| **10 Detection Rules** | Pattern-matching threat engine covering credential leaks, timing oracles, calibration harvesting, IDOR, and more |
| **Cross-Rule Correlation** | Multi-stage campaign detection (4 correlation patterns) with severity escalation |
| **STIX 2.1 Export** | One-click export of all active threats as STIX bundles for SIEM integration (Splunk, Sentinel, QRadar) |
| **GitHub Token Scanning** | Automated detection of exposed IBM Quantum API tokens in public repositories |
| **Adaptive Baselines** | Exponential moving average (EMA) baselines with z-score anomaly detection for hardware health |
| **WebSocket Streaming** | Live telemetry push to the browser with 30-second update intervals |
| **Scenario Replay** | Demo mode with mock data for presentations, training, and DEFCON demos |
| **REST API** | Full REST API with health checks, snapshot retrieval, threat querying, and filtered exports |
| **Security Hardening** | Rate limiting, security headers, optional API key authentication, CORS controls |
| **Multi-Platform Support** | IBM Quantum (live), with planned support for Amazon Braket and Azure Quantum |

## Detection Rules

The QVis threat engine implements 10 detection rules mapped to the Q-ATT&CK framework:

| Rule | Technique ID | Name | Severity | Description |
|---|---|---|---|---|
| RULE_001 | QTT017 | Credential Exposure | Critical | Detects exposed quantum API tokens in public GitHub repositories |
| RULE_002 | QTT002 | Calibration Harvesting | Medium | Flags systematic extraction of backend calibration data without job submissions |
| RULE_003 | QTT003 | Timing Oracle | High | Detects repeated submission of identity-heavy circuits for QPU characterization |
| RULE_004 | QTT009 | Tenant Probing | High | Identifies cross-tenant job ID probing and unauthorized access attempts |
| RULE_005 | QTT008 | Resource Exhaustion | Medium | Flags circuits with depth exceeding 85% of the backend maximum |
| RULE_006 | QTT011 | IP Extraction | Critical | Detects large-scale sequential IDOR enumeration campaigns |
| RULE_007 | QTT005 | Scope Violation | High | Monitors for repeated access denied (403) errors on admin endpoints |
| RULE_008 | HEALTH | Hardware Degradation | Info | Tracks qubit T1 coherence time drops below 60% of historical baseline |
| RULE_009 | QTT012 | Multi-Backend Recon | High | Detects concurrent access to 3+ backends from the same source |
| RULE_010 | QTT013 | Anomalous Circuit | Medium | Flags circuits with unusually high measurement-to-gate ratios |

### Correlation Patterns

The cross-rule correlation engine detects multi-stage attack campaigns:

| Pattern | Triggering Techniques | Window | Escalated Severity |
|---|---|---|---|
| Coordinated Reconnaissance | QTT003 + QTT002 | 30 min | Critical |
| Pre-Attack Staging | QTT017 + QTT003 | 60 min | Critical |
| Enumeration Campaign | QTT009 + QTT011 | 15 min | Critical |
| Resource Abuse Chain | QTT008 + QTT005 | 30 min | High |

## The Visual Language

| Visual Effect | Q-ATT&CK Technique | What it means |
| :--- | :--- | :--- |
| **Particle Leak** (Red particles escaping) | QTT017 Credential Exposure | A valid API token or credential has been found in a public repository or insecure location. |
| **Timing Ring** (Expanding orange rings) | QTT003 Timing Oracle | An attacker is submitting identity-heavy circuits to characterize system noise or timing patterns. |
| **Calibration Drain** (Green funnel) | QTT002 Calibration Harvesting | Systematic extraction of backend properties and calibration data without job submission. |
| **Color Bleed** (Foreign color particles) | QTT009 Tenant Probing | Unauthorized cross-tenant job access attempts or ID probing. |
| **Vortex** (Dark sphere & disc) | QTT011 IP Extraction | Sequential IDOR probes or successful large-scale intellectual property exfiltration. |
| **Interference** (Static/chaotic lines) | QTT008 Resource Exhaustion | Submitting excessively deep circuits to consume operational limits. |

## API Documentation

### Base URL

```
http://localhost:8000
```

### Endpoints

#### Health Check

```
GET /api/health
```

Returns API status, active collector, and connected platforms. Not behind authentication.

**Response:**
```json
{
  "status": "ok",
  "demo_mode": true,
  "active_collector": "mock",
  "connected_platforms": ["mock"]
}
```

#### Full Simulation Snapshot

```
GET /api/snapshot
```

Returns the complete current simulation state including all backends, threats, entanglement pairs, and platform health metrics.

#### Backend List

```
GET /api/backends
```

Returns all tracked quantum backend nodes with calibration data, threat levels, and qubit counts.

#### Threat Feed

```
GET /api/threats
GET /api/threats?severity=critical
```

Returns active threat events. Supports optional `severity` filter (critical, high, medium, low, info).

#### Threat Detail

```
GET /api/threat/{threat_id}
```

Returns detailed evidence, remediation steps, and metadata for a specific threat.

#### Threat History

```
GET /api/threats/history
```

Returns deduplicated threat history tracking all unique threats across sessions.

#### STIX 2.1 Export

```
GET /api/threats/export/stix
```

Exports all active threats as a [STIX 2.1](https://oasis-tcs.github.io/cti-documentation/stix/) Bundle for SIEM integration. Each threat becomes a STIX Indicator object with confidence scores mapped from severity levels, custom `x-qvis-threat` extensions containing evidence and visual metadata.

**Response:**
```json
{
  "type": "bundle",
  "id": "bundle--qvis-export-20241027100000",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "name": "Credential exposure in public repository",
      "pattern": "[x-quantum-threat:technique_id = 'QTT017']",
      "confidence": 95,
      "labels": ["critical", "ibm_quantum"],
      "extensions": { "x-qvis-threat": { ... } }
    }
  ]
}
```

#### WebSocket

```
ws://localhost:8000/ws/simulation
```

Full-duplex WebSocket connection for live telemetry streaming. Clients receive the full simulation snapshot on connect and every 30 seconds thereafter. Supports sending `get_snapshot` and `focus_backend` messages.

**WebSocket with authentication:**
```
ws://localhost:8000/ws/simulation?token=<api_key>
```

## STIX Export & SIEM Integration

QVis provides a one-click STIX 2.1 export endpoint that converts all active threats into standardized STIX Indicators. This enables direct integration with enterprise SIEM platforms:

- **Microsoft Sentinel**: Use the STIX/TAXII data connector to ingest threat feeds
- **Splunk**: Use the STIX app for Splunk or the REST Modular Input
- **IBM QRadar**: Native STIX import via the threat intelligence module
- **Elastic Security**: Import via the STIX timeline integration

Each STIX Indicator includes:
- Standard fields: `type`, `id`, `name`, `description`, `pattern`, `confidence`, `labels`
- QVis extension (`x-qvis-threat`): `backend_id`, `visual_effect`, `visual_intensity`, `remediation`, `evidence`

Confidence scores are mapped from severity: critical=95, high=80, medium=60, low=40, info=20.

## Scenario Replay (Demo Mode)

QVis includes a built-in demo mode with realistic mock data for presentations, training, and evaluation:

```bash
# Demo mode is enabled by default (no IBM Quantum token configured)
uvicorn backend.main:app

# Or explicitly enable demo mode
DEMO_MODE=true uvicorn backend.main:app
```

The demo mode features:
- **4 mock backends**: ibm_sherbrooke, ibm_kyoto, ibm_brisbane, ibm_qasm_simulator
- **Pre-loaded threats**: Credential exposure (QTT017), timing oracle (QTT003), calibration harvesting (QTT002), resource exhaustion (QTT008)
- **Dynamic variation**: Calibration values fluctuate realistically; threats randomly appear and resolve
- **Full API compatibility**: All endpoints return realistic data identical to live mode

For a scripted 3-minute demo, see [docs/defcon-demo-script.md](docs/defcon-demo-script.md).

## What Problem This Solves

Quantum computers are rapidly evolving, and their integration into cloud environments presents novel attack surfaces. Standard security dashboards fail to convey the physical and statistical nature of quantum workloads. A spreadsheet of API calls doesn't communicate the threat of an attacker mapping the noise profile of a specific QPU.

QVis bridges this gap. By mapping the security telemetry to a physical simulation, it allows security teams to monitor their quantum infrastructure in real-time, instantly spotting anomalies. 

## Quick Start

### Option 1: Local Development

1. Clone the repository: `git clone https://github.com/f2025408135-cyber/qvis.git`
2. Create and activate a Python virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Copy the environment template: `cp .env.example .env`
5. Run the application backend: `uvicorn backend.main:app`
6. In a new terminal, serve the frontend: `python -m http.server 3000 --directory frontend`
7. Open `http://localhost:3000` in your browser.

### Option 2: Docker

```bash
# Build and run with Docker Compose
docker compose up --build

# Access the application
open http://localhost:8000
```

See [Dockerfile](Dockerfile) and [docker-compose.yml](docker-compose.yml) for configuration options.

## Connecting to Real IBM Quantum

By default, QVis runs in demo mode with mock data. To connect to real IBM Quantum backends:

1. Get an API token from https://quantum.ibm.com/account
2. Open your `.env` file.
3. Set `DEMO_MODE=false` and `IBM_QUANTUM_TOKEN=your_token_here`
4. Restart the backend

### What Works with Real Data
- Live backend calibration monitoring (T1, T2, readout error, gate error)
- Real job history analysis (timing oracle detection, resource exhaustion)
- Backend health anomaly detection
- Credential exposure scanning (with GitHub token)

### What Requires Internal Platform Access
- Cross-tenant access pattern detection (no public audit log)
- IDOR / unauthorized job access detection (no access logs)
- Token scope violation detection (IBM internal)

## Architecture

With real data enabled:

    IBM Quantum API ──┐
                      ├──→ IBMQuantumCollector ──→ ThreatAnalyzer ──→ WebSocket ──→ Frontend
    GitHub API ───────┘         (rules.py)                               (Three.js)

With demo mode (default):

    MockCollector (inline data) ──→ ThreatAnalyzer ──→ WebSocket ──→ Frontend

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DEMO_MODE` | `true` | Enable mock data collector |
| `UPDATE_INTERVAL_SECONDS` | `30` | Telemetry refresh interval |
| `IBM_QUANTUM_TOKEN` | `""` | IBM Quantum API token |
| `GITHUB_TOKEN` | `""` | GitHub PAT for token scanning (repo scope) |
| `AUTH_ENABLED` | `false` | Enable API key authentication |
| `API_KEY` | `""` | API key for protected endpoints |
| `RATE_LIMIT` | `60/60` | Rate limit (requests/period in seconds) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
| `LOG_FORMAT` | `console` | Log format: `console` or `json` |
| `SLACK_WEBHOOK_URL` | `""` | Slack alerting webhook |
| `DISCORD_WEBHOOK_URL` | `""` | Discord alerting webhook |
| `WEBHOOK_URL` | `""` | Generic webhook URL for alerting |

## Q-ATT&CK Integration

The detection engine uses techniques mapped directly to the [Q-ATT&CK](docs/quantum-threat-taxonomy.md) framework, ensuring standardized terminology for quantum-specific threats. See the full [Quantum Threat Taxonomy Whitepaper](docs/quantum-threat-taxonomy.md) for detailed documentation of every technique, including MITRE ATT&CK mappings, detection methodology, and false positive considerations.

## Limitations & Roadmap

Please note the current state of the application:
- **IBM Quantum collector** dynamically tracks metrics, however, specific endpoints mimicking internal access rules are stubbed since they aren't publicly fetchable.
- **AWS Braket support** is planned but not currently implemented.
- **No authentication** is present by default. This is designed strictly as a local demonstration tool (enable with `AUTH_ENABLED=true`).

## Contributing

We welcome contributions! To add new detection rules:
1. Define the rule logic in `backend/threat_engine/rules.py`.
2. Implement the visual effect representation in `frontend/js/simulation/ThreatVisuals.js`.
3. Add tests in `tests/test_threat_engine.py`.
4. Document the technique in `docs/quantum-threat-taxonomy.md`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Responsible Use

This tool is strictly for research purposes and authorized platform monitoring only. Ensure you have explicit permission before connecting any credentials or monitoring external infrastructure.
