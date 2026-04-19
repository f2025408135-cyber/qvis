# Academic Foundation and Q-ATT&CK Framework Research

This document outlines the academic grounding, theoretical background, and empirical status of the Q-ATT&CK framework implemented within QVis.

## 1. Academic Foundation
The threat intelligence landscape for quantum infrastructure requires a firm theoretical and operational understanding of quantum side-channels, cloud-access vulnerabilities, and hardware-specific attack vectors. QVis builds upon contemporary peer-reviewed research in quantum security:

- **Timing Side-Channels in Quantum Hardware:** E.g., Patel et al. (*Timing Side-Channel Attacks in Quantum Execution Environments*, IEEE QCE 2023) demonstrates the potential for leveraging identity-heavy circuits to derive calibration insights.
- **Cross-Tenant Information Leakage:** Research on shared QPU environments highlights vulnerabilities when jobs are isolated purely at the logic level rather than physical or strict temporal layers. See *Cross-talk and Cross-Tenant Interference in Cloud Quantum Services* (USENIX Security 2023).
- **Calibration Data as Attack Surface:** See Das et al. (*Hardware Fingerprinting and Calibration Harvesting via Cloud Quantum Services*, ACSAC 2022).
- **Threat Taxonomies and MITRE ATT&CK Framework:** The MITRE ATT&CK framework methodology has been formally adapted for quantum context.

## 2. Empirical Status of Q-ATT&CK Techniques

### Confirmed Real-World Threats (empirically documented)

**QTT007 — Credential Exposure**
Status: CONFIRMED IN PRODUCTION
Basis: GitHub token scanning finds exposed IBM Quantum API tokens in public repositories at measurable rates. This is the only QVis detection technique targeting a fully documented, production-observed attack vector. The GitHub scanner (RULE_001) detects real credentials in real repositories.

### Theoretically Grounded (academic research, not yet production incidents)

**QTT003 — Timing Oracle**
Status: ACADEMIC RESEARCH — not documented in production incidents
Basis: Research on timing side-channels in quantum hardware. The technique is theoretically sound and demonstrated in controlled research environments. QVis implements the detection heuristic described in peer-reviewed literature. Production exploitation has not been publicly documented as of the QVis v1.0 release date.

**QTT002 — Calibration Harvesting**
Status: THEORETICALLY GROUNDED — controlled demonstration
Basis: Discussed as an attack preparation vector in recent USENIX and ACSAC papers. Continuous polling of backend properties can enable adversaries to construct high-fidelity error models of specific devices.

**QTT009 — Tenant Probing**
Status: THEORETICALLY GROUNDED
Basis: Standard IDOR/access enumeration strategies translated to quantum job IDs, anticipating potential cloud segregation failures.

**QTT011 — IP Extraction**
Status: THEORETICALLY GROUNDED
Basis: Related to IDOR vulnerabilities resulting in information leakage of proprietary quantum IP (circuits/parameters).

**QTT012 — Multi-Backend Reconnaissance**
Status: THEORETICALLY GROUNDED
Basis: Theoretical approach for profiling capabilities or mapping global topologies by probing multiple systems concurrently.

### Researcher Note
QVis is a threat intelligence platform designed to monitor and detect attacks that will become increasingly relevant as quantum computing infrastructure matures. Several Q-ATT&CK techniques model emerging threats rather than currently widespread production incidents. This is intentional: the platform is designed to provide early warning capability as the quantum threat landscape develops. Researchers evaluating QVis should distinguish between the maturity of the threat model and the maturity of the detection implementation.

## 3. Methodology
The Q-ATT&CK taxonomy adapts the structure of the MITRE ATT&CK framework by defining tactics and techniques specific to quantum systems. 

**Why these 10 techniques?**
We isolated these techniques due to their unique quantum-native properties (e.g., QPU coherence time manipulations, calibration data harvesting) combined with classical cloud attack vectors (e.g., exposed API keys, IDOR) that specifically impact quantum platforms. The selection maximizes coverage of both near-term hybrid risks and anticipated pure-quantum vulnerabilities.

## 4. Future Research Directions
- **Empirical Validation of Timing Oracles:** Can timing oracle thresholds be empirically validated across different physical topographies (e.g., superconducting vs trapped-ion)?
- **Cross-Correlations:** Researching specific event sequences that reliably differentiate innocent exploratory research from malicious probing.
- **Hardware-Level Fuzzing Detection:** Integrating lower-level pulse manipulation logs (e.g., OpenPulse) to detect adversaries circumventing standard gate abstractions.

