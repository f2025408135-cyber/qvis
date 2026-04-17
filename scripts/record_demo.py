#!/usr/bin/env python3
"""
QVis Demo Recording Guide
=========================
Step-by-step instructions for recording a demo GIF or video of QVis.

Usage:
    python scripts/record_demo.py

Supports:
    - asciinema (terminal recording)
    - screen recording (OBS / Peek / macOS built-in)
    - GIF generation from asciinema via agg

Prerequisites (pick one method):
    pip install asciinema          # terminal recordings
    pip install agg                # asciicast → GIF conversion
    apt install peek               # Linux: lightweight GIF recorder
    brew install obs               # cross-platform: full screen recorder
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_GIF_PATH = REPO_ROOT / "demo.gif"

STEPS = [
    {
        "name": "Start the backend server",
        "command": "uvicorn backend.main:app",
        "terminal": True,
        "narration": (
            "Start by launching the QVis backend. It loads in demo mode by default, "
            "so no IBM Quantum credentials are needed. You'll see startup logs "
            "showing 8 mock backends across three platforms."
        ),
    },
    {
        "name": "Serve the frontend",
        "command": "python -m http.server 3000 --directory frontend",
        "terminal": True,
        "narration": (
            "Open a second terminal and serve the static frontend. The 3D visualization "
            "runs entirely in the browser using Three.js — no build step required."
        ),
    },
    {
        "name": "Open the browser",
        "command": "open http://localhost:3000",
        "terminal": False,
        "narration": (
            "Open your browser to localhost:3000. The 3D topology loads immediately — "
            "you'll see 8 quantum backends rendered as particle spheres connected by "
            "entanglement lines. Backends with active threats pulse with colored effects."
        ),
    },
    {
        "name": "Show the 3D topology",
        "action": "Orbit camera around the topology using mouse drag",
        "terminal": False,
        "narration": (
            "Click and drag to orbit the camera around the topology. Each sphere "
            "represents a quantum backend — size indicates qubit count, color indicates "
            "health. Red backends have active critical threats. The glowing lines "
            "connecting them represent entanglement relationships."
        ),
    },
    {
        "name": "Click a threatened backend",
        "action": "Click on the red pulsing backend (ibm_sherbrooke)",
        "terminal": False,
        "narration": (
            "Click on one of the red backends. The threat sidebar slides open showing "
            "active threat events with severity badges, technique IDs from the Q-ATT&CK "
            "taxonomy, and remediation steps. Each threat has a unique visual effect "
            "in the 3D scene — watch for the particle leak or vortex animation."
        ),
    },
    {
        "name": "Filter threats by severity",
        "action": "Click severity filter buttons in the sidebar",
        "terminal": False,
        "narration": (
            "Use the severity filter buttons — Critical, High, Medium, Low — to narrow "
            "the threat view. This is how a SOC analyst would triage quantum security "
            "events during incident response."
        ),
    },
    {
        "name": "Show the REST API",
        "command": (
            "curl -s http://localhost:8000/api/health | python -m json.tool\n"
            "curl -s http://localhost:8000/api/threats?severity=critical | python -m json.tool"
        ),
        "terminal": True,
        "narration": (
            "Switch back to the terminal and demonstrate the REST API. The health endpoint "
            "shows connected platforms. The threats endpoint returns active events as JSON, "
            "filterable by severity. This is what your SIEM would consume."
        ),
    },
    {
        "name": "Export STIX 2.1 bundle",
        "command": (
            "curl -s http://localhost:8000/api/threats/export/stix | python -m json.tool"
        ),
        "terminal": True,
        "narration": (
            "Export all active threats as a STIX 2.1 Bundle. This is the industry-standard "
            "threat intelligence format. You can pipe this directly into Splunk, Microsoft "
            "Sentinel, or IBM QRadar for enterprise SIEM integration."
        ),
    },
    {
        "name": "Load an attack scenario",
        "command": (
            'curl -s -X POST "http://localhost:8000/api/scenario/load?name=coordinated_recon"'
        ),
        "terminal": True,
        "narration": (
            "Load a pre-built attack scenario to demonstrate cross-rule correlation. "
            "The coordinated reconnaissance scenario triggers timing oracle and calibration "
            "harvesting simultaneously, which the correlator escalates to a critical campaign "
            "event. Watch the 3D visualization respond in real time."
        ),
    },
    {
        "name": "Show campaign correlation",
        "action": "Observe the campaign alert in the threat sidebar",
        "terminal": False,
        "narration": (
            "In the browser, notice the new campaign event at the top of the threat sidebar. "
            "It shows 'Coordinated Reconnaissance' with critical severity — this was generated "
            "by the cross-rule correlator, not a single detection rule. The visual intensity "
            "is at maximum, and the campaign icon appears in the 3D scene."
        ),
    },
    {
        "name": "Reset to default",
        "command": 'curl -s -X POST "http://localhost:8000/api/scenario/reset"',
        "terminal": True,
        "narration": (
            "Reset the simulation back to default mock mode. This clears all loaded "
            "scenarios and returns to the standard demo state."
        ),
    },
]


def print_recording_guide():
    print("=" * 70)
    print("  QVis Demo Recording Guide")
    print("=" * 70)
    print()

    print("RECORDING METHODS")
    print("-" * 40)
    print()
    print("  Method 1: asciinema (terminal only)")
    print("  ------------------------------------")
    print("    asciinema record demo.cast")
    print("    # ... follow steps below ...")
    print("    # Exit with Ctrl+D or 'exit'")
    print("    asciinema upload demo.cast     # get a shareable URL")
    print()
    print("  Method 2: Screen recording (full demo)")
    print("  ----------------------------------------")
    print("    Linux:  peek                    # lightweight GIF recorder")
    print("    Linux:  OBS Studio              # full-featured recorder")
    print("    macOS:   Cmd+Shift+5            # built-in screen recording")
    print("    Windows: Win+G                  # Xbox Game Bar recorder")
    print()
    print("  Method 3: asciinema -> GIF")
    print("  -------------------------")
    print("    pip install agg")
    print("    agg demo.cast demo.gif")
    print()

    print("DEMO SCRIPT -- Step by Step")
    print("-" * 40)
    print()

    for i, step in enumerate(STEPS, 1):
        print(f"  Step {i}: {step['name']}")
        print(f"  {'-' * 38}")

        if step.get("command"):
            for line in step["command"].strip().split("\n"):
                print(f"    $ {line}")

        if step.get("action"):
            print(f"    [Mouse] {step['action']}")

        print()
        print(f"    Narration: {step['narration']}")
        print()

    print("-" * 40)
    print()
    print("POST-PRODUCTION")
    print("-" * 40)
    print()
    print(f"  1. Trim to ~60-90 seconds (attention span sweet spot)")
    print(f"  2. Add text overlays for key moments (API call, STIX export)")
    print(f"  3. Save as demo.gif in repo root:")
    print(f"     cp your_recording.gif {DEMO_GIF_PATH}")
    print(f"  4. Update README.md GIF placeholder comment to:")
    print(f"     <!-- demo.gif recorded {len(STEPS)} steps, ~90s -->")
    print()
    print("  Tips:")
    print("    - Use 1280x720 or 1920x1080 resolution")
    print("    - Set browser zoom to 100% for consistent framing")
    print("    - Use a dark terminal theme for contrast")
    print("    - Pause 2-3 seconds between steps for visual breathing room")
    print()


if __name__ == "__main__":
    print_recording_guide()
