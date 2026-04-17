<p align="center">
<pre>
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗███████╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔════╝
    ███████║███████║██║     █████╔╝ █████╗  ███████╗███████╗
    ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ╚════██║╚════██║
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗███████║███████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
    <strong>Quantum Threat Topology Engine</strong>
</pre>
</p>

<p align="center">
  Real-time 3D security visualization for quantum cloud infrastructure<br>
  <strong>10 detection rules</strong> &middot; <strong>3 platforms</strong> &middot; <strong>STIX 2.1</strong> &middot; <strong>Q-ATT&CK mapped</strong>
</p>

<p align="center">
  <!-- Add demo.gif here — record with: python scripts/record_demo.py -->
</p>

## What It Is

QVis is the first open-source platform that transforms quantum computing threat telemetry into an interactive 3D visualization. It continuously monitors IBM Quantum, Amazon Braket, and Azure Quantum through 10 custom detection rules mapped to a novel **Q-ATT&CK** taxonomy, then renders the entire attack surface as a living particle simulation. Credential leaks bleed red particles, timing oracles pulse as expanding orange rings, and coordinated multi-stage campaigns cascade across the topology in real time. No existing tool bridges the gap between quantum platform security telemetry and human intuition — QVis closes that gap.

## The Problem

- A Starling-class quantum computer running your company's drug discovery algorithm is being silently characterized by an adversary who submits thousands of identity-gate circuits to map its noise profile — and you have no way to see it happening.
- Your intern's IBM Quantum API token was committed to a public GitHub repo three months ago, and someone has been quietly submitting jobs under your account — but your security team only monitors classical cloud infrastructure.
- A competitor is systematically probing your quantum cloud tenant via sequential job ID enumeration, harvesting calibration data across multiple backends to fingerprint your exact hardware configuration — and your SIEM has no quantum-aware detection rules to flag it.

<p align="center">

[![Build Status](https://img.shields.io/github/actions/workflow/status/f2025408135-cyber/qvis/ci.yml?branch=main&style=flat-square)](https://github.com/f2025408135-cyber/qvis/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-ff6600.svg?style=flat-square)](https://oasis-tcs.github.io/cti-documentation/stix/)
[![Q-ATT&CK](https://img.shields.io/badge/Q--ATT&CK-Mapped-9b59b6.svg?style=flat-square)](docs/quantum-threat-taxonomy.md)

</p>

## Quick Start

```bash
git clone https://github.com/f2025408135-cyber/qvis.git
cd qvis && pip install -r requirements.txt
uvicorn backend.main:app & python -m http.server 3000 --directory frontend
open http://localhost:3000
```

No credentials required — demo mode ships with realistic mock data for 8 backends across IBM, Braket, and Azure.

## Q-ATT&CK Taxonomy

| ID | Technique Name | Severity | Visual Effect |
|----|---------------|----------|---------------|
| QTT002 | Calibration Harvesting | Medium | `calibration_drain` |
| QTT003 | Timing Oracle | High | `timing_ring` |
| QTT005 | Token Scope Violation | High | `interference` |
| QTT008 | Resource Exhaustion | Medium | `interference` |
| QTT009 | Tenant Probing | High | `color_bleed` |
| QTT011 | IP Extraction | Critical | `vortex` |
| QTT012 | Multi-Backend Reconnaissance | High | `color_bleed` |
| QTT013 | Anomalous Circuit Composition | Medium | `interference` |
| QTT017 | Credential Exposure | Critical | `particle_leak` |
| HEALTH | Hardware Degradation | Info | `calibration_drain` |

Full taxonomy with TTP mappings: [`docs/quantum-threat-taxonomy.md`](docs/quantum-threat-taxonomy.md)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        PLATFORMS                            │
│  IBM Quantum ──┐   Amazon Braket ──┐   Azure Quantum ──┐  │
│  GitHub API  ──┘                   ┘                   │  │
└──────┬──────────────────┬──────────────────┬────────────┘
       │                  │                  │
       ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    COLLECTOR LAYER                          │
│  IBMQuantumCollector │ BraketCollector │ AzureQuantumCollector│
│  GitHubScanner       │ MockCollector   │ ScenarioLoader      │
└──────────────────────────┬──────────────────────────────────┘
                           │ SimulationSnapshot
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    THREAT ENGINE                             │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ 10 Detection │──│  Baseline    │──│ Correlator (4     │ │
│  │ Rules        │  │ Manager(EMA) │  │ campaign patterns)│ │
│  └──────────────┘  └──────────────┘  └───────────────────┘ │
│  SQLite persistence · ThresholdConfig · Calibration mode     │
└──────────────────────────┬──────────────────────────────────┘
                           │ ThreatEvent[] + SimulationSnapshot
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ REST API │ │ WebSocket│ │ STIX 2.1 │
        │ (FastAPI)│ │ Stream   │ │ Export   │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             ▼            ▼            ▼
        ┌─────────────────────────────────────┐
        │         FRONTEND (Three.js)         │
        │  3D particle topology · Panels ·    │
        │  Threat sidebar · Backend inspector │
        └─────────────────────────────────────┘
```

## Detection Rules

| Rule | Technique | What It Detects |
|------|-----------|-----------------|
| RULE_001 | QTT017 | Exposed quantum API tokens in public GitHub repositories |
| RULE_002 | QTT002 | Systematic calibration data harvesting without job submissions |
| RULE_003 | QTT003 | Repeated identity-heavy circuit submissions for QPU timing characterization |
| RULE_004 | QTT009 | Cross-tenant job ID probing via failed access attempts |
| RULE_005 | QTT008 | Circuits exceeding 85% of backend maximum depth |
| RULE_006 | QTT011 | Large-scale sequential IDOR enumeration via 404 error patterns |
| RULE_007 | QTT005 | Repeated 403 errors on admin-only API endpoints |
| RULE_008 | HEALTH | Qubit T1 coherence time drops below 60% of historical baseline |
| RULE_009 | QTT012 | Concurrent access to 3+ backends from the same source |
| RULE_010 | QTT013 | Circuits with abnormally high measurement-to-gate ratios |

All thresholds are configurable via `ThresholdConfig` or auto-calibrated from live platform data using `python -m backend.main --calibrate`. Test suite provides 100% coverage of rules and correlator: `pytest tests/ --cov=backend/threat_engine`.

## Connecting Live Platforms

### IBM Quantum

```bash
echo "IBM_QUANTUM_TOKEN=your_token_here" > .env
echo "DEMO_MODE=false" >> .env
uvicorn backend.main:app
```

Live backend calibration monitoring, job history analysis, health anomaly detection, and GitHub token scanning. Requires `qiskit-ibm-runtime`.

### Amazon Braket

```bash
pip install boto3 amazon-braket-sdk
echo "AWS_ACCESS_KEY_ID=your_key" >> .env
echo "AWS_SECRET_ACCESS_KEY=your_secret" >> .env
```

Read-only device metadata and gate fidelity from Braket backends (IonQ, OQC, Rigetti). Falls back to mock if credentials are absent.

### Azure Quantum

```bash
pip install azure-quantum
echo "AZURE_QUANTUM_SUBSCRIPTION_ID=your_sub" >> .env
```

Read-only target metadata from Azure Quantum workspaces (IonQ, Quantinuum). Falls back to mock if credentials are absent.

## SIEM Integration

QVis exports all active threats as [STIX 2.1](https://oasis-tcs.github.io/cti-documentation/stix/) Bundles with custom `x-qvis-threat` extensions:

```bash
# Fetch all threats as STIX
curl -s http://localhost:8000/api/threats/export/stix | python -m json.tool

# Filter to critical-only
curl -s "http://localhost:8000/api/threats/export/stix?severity=critical" | \
  python -m json.tool
```

Compatible with Microsoft Sentinel, Splunk (STIX app), IBM QRadar, and Elastic Security. Confidence mapping: critical=95, high=80, medium=60, low=40, info=20.

## Contributing

QVis is an open research platform — contributions are welcome.

- **New detection rules** — Add to `backend/threat_engine/rules.py`, map to a Q-ATT&CK technique, implement a visual effect in `frontend/js/simulation/ThreatVisuals.js`, and add tests in `tests/test_rules.py`.
- **New platform collectors** — Subclass `BaseCollector` in `backend/collectors/`, implement the `collect()` method returning a `SimulationSnapshot`, and register in `backend/collectors/aggregator.py`.
- **Improved visualizations** — The 3D frontend uses Three.js with a modular renderer architecture. New particle effects, camera behaviours, and UI panels go in `frontend/js/renderers/` and `frontend/js/ui/`.

Run tests with `pytest tests/ --cov=backend/threat_engine --cov-report=term`.

## Research Applications

- **Quantum threat modeling validation** — Use QVis's Q-ATT&CK taxonomy and live detection rules to empirically validate threat models from USENIX Sec 2023 and ACSAC 2022 papers against real quantum cloud telemetry.
- **Security education and training** — The built-in scenario replay system with pre-loaded attack simulations provides a hands-on teaching environment for quantum security courses and CTF competitions.
- **Cross-platform security comparative analysis** — Monitor IBM Quantum, Braket, and Azure Quantum simultaneously to compare their security postures, audit logging capabilities, and exposure surfaces under identical detection methodologies.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [Q-ATT&CK Quantum Threat Taxonomy](docs/quantum-threat-taxonomy.md) — novel framework for quantum-specific adversary techniques
- [MITRE ATT&CK](https://attack.mitre.org/) — foundational cyber threat taxonomy that inspired Q-ATT&CK's structure
- [IBM Quantum](https://quantum.ibm.com/) — for providing open access to real quantum hardware through Qiskit Runtime
- [Three.js](https://threejs.org/) — the 3D rendering engine that powers QVis's threat topology visualization
