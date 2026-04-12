# QVis — Quantum Threat Topology Engine

```text
    ___ _    ___     
   / _ \ |  / (_)____
  / /_)/ | / / / ___/
 / ___/| |/ / (__  ) 
/_/    |___/_/____/  
```

QVis is a real-time visual threat intelligence platform for quantum cloud infrastructure. It takes abstract security telemetry from quantum platforms like IBM Quantum and renders the entire attack topology as a living 3D particle simulation in the browser. 

The entire field of quantum security risk communication is broken. Security findings are just abstract JSON that no CISO, executive, or policymaker can look at and intuitively grasp. QVis makes quantum cloud attack surfaces visceral and immediately communicable to any audience.

## The visual language

| Visual Effect | Q-ATT&CK Technique | What it means |
| :--- | :--- | :--- |
| **Particle Leak** (Red particles escaping) | QTT017 Credential Exposure | A valid API token or credential has been found in a public repository or insecure location. |
| **Timing Ring** (Expanding orange rings) | QTT003 Timing Oracle | An attacker is submitting identity-heavy circuits to characterize system noise or timing patterns. |
| **Calibration Drain** (Green funnel) | QTT002 Calibration Harvesting | Systematic extraction of backend properties and calibration data without job submission. |
| **Color Bleed** (Foreign color particles) | QTT009 Tenant Probing | Unauthorized cross-tenant job access attempts or ID probing. |
| **Vortex** (Dark sphere & disc) | QTT011 IP Extraction | Sequential IDOR probes or successful large-scale intellectual property exfiltration. |
| **Interference** (Static/chaotic lines) | QTT008 Resource Exhaustion | Submitting excessively deep circuits to consume operational limits. |

## What problem this solves

Quantum computers are rapidly evolving, and their integration into cloud environments presents novel attack surfaces. Standard security dashboards fail to convey the physical and statistical nature of quantum workloads. A spreadsheet of API calls doesn't communicate the threat of an attacker mapping the noise profile of a specific QPU.

QVis bridges this gap. By mapping the security telemetry to a physical simulation, it allows security teams to monitor their quantum infrastructure in real-time, instantly spotting anomalies. 

## Quick start

1. Clone the repository: `git clone https://github.com/f2025408135-cyber/qvis.git`
2. Create and activate a Python virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Copy the environment template: `cp .env.example .env`
5. Run the application backend: `uvicorn backend.main:app`
6. In a new terminal, serve the frontend: `python -m http.server 3000 --directory frontend`
7. Open `http://localhost:3000` in your browser.

## Connecting to Real IBM Quantum

By default, QVis runs in demo mode with mock data. To connect to real IBM Quantum backends:

1. Get an API token from https://quantum.ibm.com/account
2. Open your `.env` file.
3. Set `DEMO_MODE=false` and `IBM_QUANTUM_TOKEN=your_token_here`
4. Restart the backend

### What Works with Real Data
- ✅ Live backend calibration monitoring (T1, T2, readout error, gate error)
- ✅ Real job history analysis (timing oracle detection, resource exhaustion)
- ✅ Backend health anomaly detection
- ✅ Credential exposure scanning (with GitHub token)

### What Requires Internal Platform Access
- ❌ Cross-tenant access pattern detection (no public audit log)
- ❌ IDOR / unauthorized job access detection (no access logs)
- ❌ Token scope violation detection (IBM internal)

## Architecture

With real data enabled:

    IBM Quantum API ──┐
                      ├──→ IBMQuantumCollector ──→ ThreatAnalyzer ──→ WebSocket ──→ Frontend
    GitHub API ───────┘         (rules.py)                               (Three.js)

With demo mode (default):

    MockCollector (inline data) ──→ ThreatAnalyzer ──→ WebSocket ──→ Frontend

## Limitations & Roadmap

Please note the current state of the application:
- **IBM Quantum collector** dynamically tracks metrics, however, specific endpoints mimicking internal access rules are stubbed since they aren't publicly fetchable.
- **AWS Braket support** is planned but not currently implemented.
- **No authentication** is present. This is designed strictly as a local demonstration tool.

## Q-ATT&CK integration

The detection engine uses techniques mapped directly to the Q-ATT&CK framework, ensuring standardized terminology for quantum-specific threats.

## Contributing

We welcome contributions! To add new detection rules:
1. Define the rule logic in `backend/threat_engine/rules.py`.
2. Implement the visual effect representation in `frontend/js/simulation/ThreatVisuals.js`.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Responsible use

This tool is strictly for research purposes and authorized platform monitoring only. Ensure you have explicit permission before connecting any credentials or monitoring external infrastructure.
