# DEFCON Demo Script — QVis Quantum Threat Topology Engine

> **Total Runtime: 3 minutes**
> **Audience: Security researchers, CISOs, DEFCON attendees**
> **Pre-requisites: QVis running in demo mode, browser on localhost:3000**

---

## Pre-Show Setup (Before Going Live)

```bash
# Terminal 1: Start the backend
cd /home/z/my-project/qvis
source venv/bin/activate
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Serve the frontend
cd /home/z/my-project/qvis
python -m http.server 3000 --directory frontend

# Terminal 3: Keep this open for live commands during the demo
curl -s http://localhost:8000/api/health | python -m json.tool
```

Verify health check returns `"status": "ok"` and `"demo_mode": true`.

---

## Section 1: Dashboard Idle State (0:00 – 0:30)

### What to Do

1. Open browser to `http://localhost:3000`
2. Let the 3D particle simulation load — give it 3-5 seconds
3. Point at the four backend nodes floating in the simulation space
4. Highlight the threat panel on the right

### What to Say

> "This is QVis — a real-time threat intelligence platform for quantum cloud infrastructure. What you're seeing is a living 3D topology of four IBM Quantum backends. Each node represents a real quantum processor — Sherbrooke, Kyoto, Brisbane, and a simulator."
>
> "The color and glow of each node reflects its threat level. Right now you can see Sherbrooke is glowing red because we've already detected a critical credential exposure. The lines connecting the backends represent entanglement relationships in our simulation model."
>
> "On the right panel, you see all active threat detections ranked by severity. This is your real-time threat feed. The entire visualization is driven by a WebSocket stream — the backend pushes new telemetry every 30 seconds and the simulation updates instantly."

### Key UI Elements to Highlight

- **Backend nodes**: Size = qubit count, color = threat level
- **Particle effects**: Red particles = credential leak (QTT017), Orange rings = timing oracle (QTT003)
- **Threat panel**: Sorted by severity (critical → high → medium → info)
- **HUD overlay**: Total threats, platform health score, backend count

---

## Section 2: Credential Exposure Detection (0:30 – 1:00)

### What to Do

1. Keep the browser visible — the demo mock data already includes a QTT017 credential exposure on Sherbrooke
2. Click on the Sherbrooke node or the credential exposure event in the threat panel
3. Open a second terminal and run:

```bash
# Show the raw threat data via API
curl -s http://localhost:8000/api/threats | python -m json.tool | head -40

# Show just the critical threats
curl -s "http://localhost:8000/api/threats?severity=critical" | python -m json.tool
```

4. Point out the evidence field showing the GitHub repository, file, and line number

### What to Say

> "Right now, QVis has detected a critical credential exposure — a valid IBM Quantum API token found in a public GitHub repository. The red particle leak effect you see emanating from the Sherbrooke node represents data bleeding out of the platform."
>
> "Let me pull the raw detection data. [Run curl command.] You can see the full evidence chain — the exact repository, the file, and the line where the token was found. This is rule RULE_001 scanning GitHub's code search API for exposed QiskitRuntimeService tokens."
>
> "What makes this dangerous is that this token gives full authenticated access to the quantum platform. An attacker with this token can submit jobs, read results, and consume someone else's quantum compute allocation."

---

## Section 3: Timing Oracle + Calibration Harvesting Correlation (1:00 – 2:00)

### What to Do

1. The mock data includes both QTT003 (Timing Oracle on Sherbrooke) and QTT002 (Calibration Harvesting on Kyoto)
2. Pan the 3D view between Sherbrooke (orange timing rings) and Kyoto (green calibration drain)
3. In the terminal, show the threat history endpoint which includes correlation data:

```bash
# Show all active threats including correlation campaigns
curl -s http://localhost:8000/api/threats/history | python -m json.tool | head -80

# Count threats by severity
curl -s http://localhost:8000/api/snapshot | python -m json.tool | python -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['threats_by_severity'], indent=2))"
```

4. If the correlator has detected the "Coordinated Reconnaissance" campaign (QTT003 + QTT002 on the same backend), highlight it

### What to Say

> "Now watch what happens when we look at this more broadly. On Sherbrooke, we see orange timing rings — that's a timing oracle detection. Someone is submitting identity-heavy circuits to characterize the QPU's execution timing."
>
> "And on Kyoto, there's a green calibration drain — someone is harvesting backend properties at 75 times the rate of actual job submissions. They're building a noise model."
>
> "QVis runs a cross-rule correlation engine that looks for multi-stage attack campaigns. If both of these techniques — timing oracle and calibration harvesting — appear on the same backend within 30 minutes, the system escalates to a Critical campaign alert. This is how you detect an adversary systematically characterizing a quantum processor before launching a targeted attack."
>
> "Each threat has a 5-minute deduplication window, so you see a steady-state view of active threats, not an alert storm."

---

## Section 4: STIX Export + SIEM Integration (2:00 – 2:30)

### What to Do

1. Export all threats as a STIX 2.1 bundle:

```bash
# Export all active threats as STIX 2.1
curl -s http://localhost:8000/api/threats/export/stix | python -m json.tool | head -50

# Show just the bundle metadata and first indicator
curl -s http://localhost:8000/api/threats/export/stix | python -c "
import sys, json
bundle = json.load(sys.stdin)
print(f\"Bundle ID: {bundle['id']}\")
print(f\"Object count: {len(bundle['objects'])}\")
for obj in bundle['objects'][:2]:
    print(f\"\n  Type: {obj['type']}\")
    print(f\"  Name: {obj['name']}\")
    print(f\"  Pattern: {obj['pattern']}\")
    print(f\"  Confidence: {obj['confidence']}\")
    print(f\"  Labels: {obj['labels']}\")
"
```

2. Explain how this feeds into Splunk/Sentinel/QRadar

### What to Say

> "One click — actually, one API call — and you get every active threat as a STIX 2.1 bundle. This is the industry standard for threat intelligence sharing. You can pipe this directly into Splunk, Microsoft Sentinel, or any SIEM that speaks STIX/TAXII."
>
> "Each indicator includes the technique ID, severity-mapped confidence score, evidence chain, and even our visual effect metadata in a custom `x-qvis-threat` extension. Your SOC team doesn't need to understand quantum computing — they just see structured threat indicators with severity and remediation steps."

---

## Section 5: Timeline + Trend Analysis (2:30 – 3:00)

### What to Do

1. Show the threat history endpoint for timeline data:

```bash
# Show deduplicated threat history
curl -s http://localhost:8000/api/threats/history | python -m json.tool | python -c "
import sys, json
history = json.load(sys.stdin)
print(f'Total unique threats tracked: {len(history)}')
for t in history:
    print(f\"  [{t['severity'].upper():8s}] {t['technique_id']:30s} {t['technique_name']}\")
"

# Show full snapshot summary
curl -s http://localhost:8000/api/snapshot | python -c "
import sys, json
snap = json.load(sys.stdin)
print(f\"Snapshot: {snap['snapshot_id']}\")
print(f\"Backends: {len(snap['backends'])} | Total Qubits: {snap['total_qubits']}\")
print(f\"Active Threats: {snap['total_threats']}\")
print(f\"Severity breakdown: {snap['threats_by_severity']}\")
print(f\"Platform health: {snap['platform_health']}\")
"
```

2. Pan the 3D view to show the full topology one more time

### What to Say

> "Finally, QVis maintains a deduplicated threat history across all sessions. You can see every unique threat tracked over time — who's been probing, what backends have been targeted, and the severity trend."
>
> "The snapshot API gives you the full system state: 4 backends, 413 total qubits, 4 active threats across severity levels. Platform health is 75% — degraded by the credential exposure and the resource exhaustion on the simulator."
>
> "This is the state of quantum security visibility today. These platforms are live, these attacks are real, and until now, there's been no way to see them. QVis changes that."
>
> "Thank you. The code is open source. Check out the repo — the link is on screen."

---

## Post-Demo Resources

| Resource | URL/Command |
|---|---|
| GitHub Repository | `https://github.com/f2025408135-cyber/qvis` |
| API Health | `curl http://localhost:8000/api/health` |
| STIX Export | `curl http://localhost:8000/api/threats/export/stix` |
| Threat Feed | `curl http://localhost:8000/api/threats` |
| Full Snapshot | `curl http://localhost:8000/api/snapshot` |
| WebSocket | `ws://localhost:8000/ws/simulation` |

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Backend won't start | Check Python venv is activated, run `pip install -r requirements.txt` |
| Frontend 404 | Verify `frontend/index.html` exists, check the `--directory` path |
| No threats visible | Wait 30 seconds for first simulation cycle, or hit `/api/snapshot` |
| WebSocket disconnects | Check CORS origins — set `CORS_ORIGINS=http://localhost:3000` |
| STIX export empty | Threats must be actively detected; check `/api/threats` first |
