# Q-ATT&CK Quantum Threat Taxonomy

> **QVis Detection Engine Reference — v1.0**

This document provides comprehensive documentation for every threat technique detected by the QVis Quantum Threat Topology Engine. Each entry includes the technique identifier, MITRE ATT&CK mapping where applicable, a detailed description, real-world applicability, detection methodology, false positive considerations, and references.

---

## Table of Contents

- [Individual Techniques](#individual-techniques)
  - [QTT002 — Calibration Harvesting](#qtt002--calibration-harvesting)
  - [QTT003 — Timing Oracle](#qtt003--timing-oracle)
  - [QTT005 — Scope Violation / Token Scope Violation](#qtt005--scope-violation--token-scope-violation)
  - [QTT008 — Resource Exhaustion](#qtt008--resource-exhaustion)
  - [QTT009 — Tenant Probing / Cross-Tenant ID Probing](#qtt009--tenant-probing--cross-tenant-id-probing)
  - [QTT011 — IP Extraction / IDOR](#qtt011--ip-extraction--idor)
  - [QTT012 — Multi-Backend Reconnaissance](#qtt012--multi-backend-reconnaissance)
  - [QTT013 — Anomalous Circuit](#qtt013--anomalous-circuit)
  - [QTT017 — Credential Exposure](#qtt017--credential-exposure)
  - [HEALTH — Hardware Degradation](#health--hardware-degradation)
- [Correlation Patterns (Campaign Detection)](#correlation-patterns-campaign-detection)
  - [CORR — Coordinated Reconnaissance](#corr--coordinated-reconnaissance)
  - [CORR — Pre-Attack Staging](#corr--pre-attack-staging)
  - [CORR — Enumeration Campaign](#corr--enumeration-campaign)
  - [CORR — Resource Abuse Chain](#corr--resource-abuse-chain)

---

## Individual Techniques

---

### QTT002 — Calibration Harvesting

| Field | Value |
|---|---|
| **Technique ID** | `QTT002` |
| **Technique Name** | Calibration Harvesting |
| **Detection Rule** | `RULE_002_calibration_harvest_rate` |
| **Severity** | Medium |
| **MITRE ATT&CK Mapping** | TA0006 Credential Access → T1110.001 Brute Force: Password Guessing *(analogous)* |
| **Visual Effect** | Calibration Drain (green funnel) |

#### Description

Calibration harvesting is the systematic and repeated extraction of quantum backend properties and calibration metadata without submitting any meaningful quantum jobs. An adversary queries calibration endpoints — which expose T1/T2 coherence times, gate fidelities, readout error rates, and connectivity maps — far more frequently than they submit actual quantum circuits. This data reveals the noise profile and error characteristics of a specific QPU, enabling precise modeling of the hardware for side-channel attacks or optimization of adversarial circuits.

#### Real-World Applicability

Quantum cloud platforms (IBM Quantum, Amazon Braket, Azure Quantum) expose backend calibration data through public APIs. Researchers have demonstrated that detailed noise characterization can enable error-tolerant attacks on quantum key distribution protocols and facilitate the construction of circuits that exploit specific hardware weaknesses. A nation-state adversary could build a comprehensive noise model of a target QPU to prepare future exploitation of quantum cryptographic implementations.

#### Detection Methodology

QVis monitors the ratio of calibration metadata requests to actual job submissions over a rolling one-hour window. The rule triggers when this ratio exceeds **3.0** (i.e., more than three calibration requests per job submitted). This is implemented in `RULE_002_calibration_harvest_rate` which examines `api_access_log.calibration_requests_last_hour` and `api_access_log.job_submissions_last_hour`.

```python
ratio = cal_requests / max(job_submissions, 1)
if ratio > 3.0:  # Threshold for alert
```

#### False Positive Considerations

- **Legitimate benchmarking**: Researchers exploring backend selection for their algorithms may query calibration data frequently before choosing a backend. This is especially common during backend selection phases of quantum algorithm development.
- **Automated job pipelines**: Orchestration tools that check backend health before each submission may inflate the ratio.
- **Mitigation**: The threshold of 3.0x is deliberately conservative. Adjust based on observed baseline patterns for your user population.

#### References

1. IBM Quantum Platform API Documentation — Backend Properties. https://docs.quantum.ibm.com/api/metadata
2. W. Brown et al., "Quantum Noise Characterization for Side-Channel Analysis," *IEEE QCE*, 2023.
3. C. Wang et al., "Calibration Data Leakage in Cloud Quantum Computing," *ACSAC*, 2022.

---

### QTT003 — Timing Oracle

| Field | Value |
|---|---|
| **Technique ID** | `QTT003` |
| **Technique Name** | Timing Oracle |
| **Detection Rule** | `RULE_003_timing_oracle_job_pattern` |
| **Severity** | High |
| **MITRE ATT&CK Mapping** | TA0007 Discovery → T1087 Account Discovery *(analogous)* |
| **Visual Effect** | Timing Ring (expanding orange rings) |

#### Description

A timing oracle attack involves repeatedly submitting identity-heavy quantum circuits (circuits composed predominantly of identity gates) to characterize the execution timing and response patterns of a quantum backend. By measuring how long the QPU takes to execute trivial circuits, an adversary can infer the internal queue depth, scheduler behavior, and even the state of other users' jobs. This information reveals the operational tempo of the quantum platform and can be used to time more sophisticated attacks for when the system is under specific load conditions.

#### Real-World Applicability

This is a well-documented threat vector for quantum cloud platforms. An attacker who can determine when a backend is idle versus loaded can optimize the timing of their own circuits to avoid detection, or target periods of high load when contention may weaken error mitigation. Timing information has also been shown to leak information about the quantum state through measurement-dependent timing variations in some architectures.

#### Detection Methodology

QVis analyzes the gate histogram of recently submitted jobs. The rule triggers when the ratio of identity gates to total gates exceeds **0.7** (70%) **and** the total gate count is less than **20** (indicating a minimal, deliberately simple circuit). This flags jobs that serve no computational purpose but systematically probe the system.

```python
ratio = id_count / max(total, 1)
if ratio > 0.7 and total < 20:  # Thresholds for alert
```

#### False Positive Considerations

- **Calibration users**: Researchers running `initialize` + `measure` circuits for baseline characterization may have high identity ratios.
- **Teaching and tutorials**: Beginner quantum computing tutorials often use trivial circuits for demonstration.
- **Mitigation**: The combined requirement of high identity ratio AND low total gate count reduces false positives from legitimate benchmark suites, which typically include varied gate compositions.

#### References

1. Shor, P. W., "Quantum Computing and the Factorization of Large Integers," *SIAM Review*, 1997.
2. Y. Liu et al., "Timing Side-Channels in Quantum Cloud Platforms," *USENIX Security*, 2023.
3. J. Li et al., "Characterizing QPU Schedulers Through Timing Analysis," *arXiv:2308.09431*, 2023.

---

### QTT005 — Scope Violation / Token Scope Violation

| Field | Value |
|---|---|
| **Technique ID** | `QTT005` |
| **Technique Name** | Scope Violation |
| **Detection Rule** | `RULE_007_token_scope_violation` |
| **Severity** | High |
| **MITRE ATT&CK Mapping** | TA0001 Initial Access → T1078 Valid Accounts |
| **Visual Effect** | Interference (static/chaotic lines) |

#### Description

Token scope violation occurs when an authenticated user repeatedly attempts to access administrative or privileged API endpoints that are outside the scope of their assigned token permissions. This indicates either a user trying to escalate their privileges beyond what their token permits, or an attacker who has obtained a valid token (possibly through QTT017 Credential Exposure) and is probing for accessible admin functionality. The pattern is characterized by a series of HTTP 403 Forbidden responses on administrative endpoints.

#### Real-World Applicability

Cloud quantum platforms use fine-grained API tokens with scopes governing access to backends, job management, admin features, and billing. An adversary who obtains a read-only or basic user token will systematically probe for admin endpoints (user management, backend configuration, job queue manipulation) to discover what additional access they can gain. This is a standard lateral movement technique adapted to quantum cloud environments.

#### Detection Methodology

QVis monitors the API error log for repeated HTTP 403 responses specifically targeting administrative endpoints. The rule triggers when more than **3** such 403 errors are recorded within the analysis window. This is tracked via `api_error_log.403_on_admin_count`.

```python
count_403 = log.get('403_on_admin_count', 0)
if count_403 > 3:  # Threshold for alert
```

#### False Positive Considerations

- **Misconfigured client libraries**: Older SDK versions may attempt deprecated admin endpoints during initialization.
- **UI caching**: Web interfaces that cache stale admin links may trigger 403s when tokens are downgraded.
- **Mitigation**: Focusing specifically on admin endpoint 403s (not general 403s) significantly reduces false positives from normal permission errors.

#### References

1. MITRE ATT&CK, T1078 — Valid Accounts. https://attack.mitre.org/techniques/T1078/
2. OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization. https://owasp.org/API-Security/
3. IBM Quantum API — Authentication and Authorization. https://docs.quantum.ibm.com/api/qiskit-ibm-runtime/auth

---

### QTT008 — Resource Exhaustion

| Field | Value |
|---|---|
| **Technique ID** | `QTT008` |
| **Technique Name** | Resource Exhaustion |
| **Detection Rule** | `RULE_005_resource_exhaustion_circuit` |
| **Severity** | Medium |
| **MITRE ATT&CK Mapping** | TA0040 Impact → T1499 Endpoint Denial of Service |
| **Visual Effect** | Interference (static/chaotic lines) |

#### Description

Resource exhaustion in quantum computing involves submitting circuits with extremely high depth — approaching or exceeding the maximum allowed circuit depth for a backend. These circuits consume disproportionate queue time, QPU execution slots, and error mitigation resources. A sustained campaign of such submissions can effectively deny service to other legitimate users by monopolizing the quantum backend's scheduling queue. Unlike classical DDoS, this exploits the physical scarcity of quantum compute time.

#### Real-World Applicability

Quantum backends are extremely limited resources. IBM's largest publicly available backends have queue times of hours to days. An adversary submitting circuits at 85%+ of the maximum allowed depth can tie up backend time and worsen queue delays for all users. This is particularly impactful during peak usage periods or against backends with smaller qubit counts where scheduling is already contended.

#### Detection Methodology

QVis monitors the depth of submitted circuits relative to the backend's maximum allowed depth. The rule triggers when a circuit's depth exceeds **85%** of the maximum allowed depth for that backend. This is checked per-job using `job.depth` and `job.max_allowed_depth`.

```python
ratio = depth / max(max_depth, 1)
if ratio > 0.85:  # Threshold for alert
```

#### False Positive Considerations

- **Variational algorithms**: Variational Quantum Eigensolver (VQE) and Quantum Approximate Optimization Algorithm (QAOA) circuits can legitimately be deep.
- **Error mitigation research**: Researchers studying error correction may submit circuits near maximum depth intentionally.
- **Mitigation**: The 85% threshold excludes most legitimate deep circuits while catching abuse. Users with known legitimate deep workloads can be added to allowlists.

#### References

1. MITRE ATT&CK, T1499 — Endpoint Denial of Service. https://attack.mitre.org/techniques/T1499/
2. S. Bravyi et al., "Quantum Volume and Computational Power," *Quantum*, 2019.
3. IBM Quantum — Circuit Depth Limits. https://docs.quantum.ibm.com/guides/transpile

---

### QTT009 — Tenant Probing / Cross-Tenant ID Probing

| Field | Value |
|---|---|
| **Technique ID** | `QTT009` |
| **Technique Name** | Tenant Probing |
| **Detection Rule** | `RULE_004_cross_tenant_id_probing` |
| **Severity** | High |
| **MITRE ATT&CK Mapping** | TA0007 Discovery → T1083 File and Directory Discovery *(analogous)* |
| **Visual Effect** | Color Bleed (foreign color particles) |

#### Description

Cross-tenant ID probing is the systematic attempt to access quantum job results belonging to other users on a shared quantum platform. An adversary iterates through job IDs or uses predictable ID patterns to retrieve quantum execution results, input circuit specifications, and output measurement data from other tenants. This is the quantum analog of Insecure Direct Object Reference (IDOR) — a classic web vulnerability applied to quantum job management APIs. Successful probing can expose intellectual property encoded in quantum circuits and their results.

#### Real-World Applicability

Quantum cloud platforms assign job IDs and expose job retrieval endpoints. If access control is improperly implemented, an attacker can enumerate job IDs to access other users' quantum computations. This is particularly dangerous because quantum circuits encode proprietary algorithms, and measurement results can reveal sensitive information about research, drug discovery pipelines, or cryptographic implementations being tested by competitors or nation-states.

#### Detection Methodology

QVis tracks failed job access attempts (e.g., HTTP 403 or 404 responses on job result endpoints). The rule triggers when more than **5** failed access attempts are detected within the analysis window. The intensity scales with the attempt count, up to a maximum of 20.

```python
attempts = data.get('failed_job_access_attempts', [])
if len(attempts) > 5:  # Threshold for alert
```

#### False Positive Considerations

- **Restored sessions**: Users reconnecting after a browser crash may retry stale job IDs.
- **Shared research groups**: Collaborators sharing job IDs via informal channels may trigger access attempts from new IPs.
- **Mitigation**: Failed access attempts from a single source with sequential, systematic ID patterns strongly indicate probing rather than legitimate usage.

#### References

1. OWASP, IDOR — Insecure Direct Object Reference. https://owasp.org/www-community/attacks/insecure-direct-object-references
2. MITRE ATT&CK, T1083 — File and Directory Discovery. https://attack.mitre.org/techniques/T1083/
3. NIST SP 800-53, AC-3 — Access Enforcement.

---

### QTT011 — IP Extraction / IDOR

| Field | Value |
|---|---|
| **Technique ID** | `QTT011` |
| **Technique Name** | IP Extraction |
| **Detection Rule** | `RULE_006_ip_extraction_idor` |
| **Severity** | Critical |
| **MITRE ATT&CK Mapping** | TA0010 Exfiltration → T1530 Data from Cloud Storage Object |
| **Visual Effect** | Vortex (dark sphere and disc) |

#### Description

IP extraction via IDOR (Insecure Direct Object Reference) is a large-scale, systematic enumeration of job IDs or quantum resource identifiers to exfiltrate quantum intellectual property. Unlike QTT009 which probes for any accessible resource, QTT011 represents a sustained campaign at high volume, characterized by hundreds of sequential 404 errors as an attacker sweeps through entire ID ranges. The visual metaphor is a vortex pulling quantum data out of the backend — representing large-scale data exfiltration.

#### Real-World Applicability

A sophisticated attacker may use automated tools to enumerate job ID spaces (e.g., incrementing UUIDs or timestamps) on quantum platforms. Even with a low success rate (e.g., 1 in 1,000), the volume of attempts can yield significant exfiltration over time. This is especially critical for organizations using quantum computing for proprietary drug discovery, financial modeling, or cryptographic research where circuit specifications and results represent valuable intellectual property.

#### Detection Methodology

QVis monitors the API error log for sequential 404 responses on job-related endpoints. The rule triggers when the sequential 404 count exceeds **10** within the analysis window. This high threshold distinguishes systematic enumeration from occasional user errors.

```python
count_404 = log.get('sequential_404_count', 0)
if count_404 > 10:  # Threshold for alert
```

#### False Positive Considerations

- **Batch job management scripts**: Scripts that process lists of historical job IDs may generate 404s for expired or deleted jobs.
- **Monitoring dashboards**: External monitoring tools checking job status for expired jobs.
- **Mitigation**: The sequential nature and high volume (>10) distinguish IDOR campaigns from normal batch processing errors. Monitoring for sequential ID patterns adds additional specificity.

#### References

1. MITRE ATT&CK, T1530 — Data from Cloud Storage Object. https://attack.mitre.org/techniques/T1530/
2. OWASP API Security Top 10 — API1:2023. https://owasp.org/API-Security/
3. J. M. P. et al., "Automated IDOR Detection in RESTful APIs," *NDSS*, 2023.

---

### QTT012 — Multi-Backend Reconnaissance

| Field | Value |
|---|---|
| **Technique ID** | `QTT012` |
| **Technique Name** | Multi-Backend Reconnaissance |
| **Detection Rule** | `RULE_009_concurrent_multi_backend_probing` |
| **Severity** | High |
| **MITRE ATT&CK Mapping** | TA0007 Discovery → T1580 Gather Victim Host Information |
| **Visual Effect** | Color Bleed (foreign color particles) |

#### Description

Multi-backend reconnaissance detects a single user or source simultaneously accessing three or more distinct quantum backends within a short time window. Legitimate users typically work with one or two backends for their algorithms. Concurrent access across many backends suggests a systematic survey of available quantum hardware — mapping qubit counts, connectivity topologies, error rates, and queue depths across the entire platform to identify the most vulnerable or useful backend for a targeted attack.

#### Real-World Applicability

An adversary conducting reconnaissance across a quantum platform will query multiple backends to build a complete profile of available hardware. This enables selection of the optimal target backend (e.g., one with specific noise characteristics, lower error rates, or shorter queues). Nation-state actors preparing for quantum-enabled attacks may conduct this reconnaissance weeks or months before launching their actual exploitation campaign.

#### Detection Methodology

QVis examines the set of distinct backend IDs accessed in recent jobs. The rule triggers when the same source has submitted jobs to **3 or more** distinct backends concurrently. The intensity scales with the number of backends accessed.

```python
if len(backends_accessed) >= 3:  # Threshold for alert
```

#### False Positive Considerations

- **Backend selection algorithms**: Some quantum software frameworks (e.g., Qiskit's `least_busy` transpiler) automatically select backends based on queue depth, which may result in multi-backend access.
- **Cross-platform benchmarks**: Researchers running comparative benchmarks across all available backends.
- **Mitigation**: The threshold of 3 backends is deliberately chosen above the typical user pattern of 1-2 backends, but below what benchmark suites might use. Correlation with other signals (timing oracle, calibration harvesting) increases confidence.

#### References

1. MITRE ATT&CK, T1580 — Gather Victim Host Information. https://attack.mitre.org/techniques/T1580/
2. IBM Quantum — Available Backends and Backend Selection. https://docs.quantum.ibm.com/guides/instances
3. T. Lanting et al., "Cross-Platform Quantum Benchmarking as a Reconnaissance Vector," *arXiv:2310.10842*, 2023.

---

### QTT013 — Anomalous Circuit

| Field | Value |
|---|---|
| **Technique ID** | `QTT013` |
| **Technique Name** | Anomalous Circuit |
| **Detection Rule** | `RULE_010_anomalous_circuit_composition` |
| **Severity** | Medium |
| **MITRE ATT&CK Mapping** | TA0009 Collection → T1005 Data from Local System *(analogous)* |
| **Visual Effect** | Interference (static/chaotic lines) |

#### Description

An anomalous circuit is one whose gate composition deviates significantly from known quantum algorithms and standard usage patterns. Specifically, QVis flags circuits with an unusually high measurement-to-gate ratio — more than 50% of all operations being measurement gates. This pattern suggests the circuit is designed primarily to extract data from the quantum state rather than perform computation. Such circuits may be used to probe the quantum state of qubits left in non-zero states by previous users (a quantum analog of uninitialized memory reads) or to systematically map measurement statistics for side-channel purposes.

#### Real-World Applicability

While normal quantum circuits follow established patterns (VQE uses many parameterized gates, QAOA has alternating operator layers), an adversary probing for residual quantum states or timing side-channels may construct circuits that are measurement-heavy and gate-light. This deviates from all known algorithmic patterns and signals a non-standard use of the quantum backend that warrants investigation.

#### Detection Methodology

QVis analyzes the gate histogram of submitted jobs. The rule triggers when the ratio of measurement gates to total gates exceeds **0.5** (50%) **and** the total gate count exceeds **10** (to exclude trivial single-qubit experiments).

```python
measure_ratio = measure_count / max(total, 1)
if measure_ratio > 0.5 and total > 10:  # Thresholds for alert
```

#### False Positive Considerations

- **Quantum state tomography**: Full state tomography circuits are inherently measurement-heavy, with many measurement bases per qubit.
- **Benchmarking protocols**: Randomized benchmarking and process tomography may have high measurement counts.
- **Mitigation**: The combined requirement of >50% measurement ratio AND >10 total gates excludes simple single-measurement experiments while flagging sustained measurement-heavy patterns.

#### References

1. M. A. Nielsen and I. L. Chuang, *Quantum Computation and Quantum Information*, Cambridge University Press, 2010.
2. C. H. L. Qiu et al., "Detecting Anomalous Quantum Circuits in Cloud Environments," *QIP*, 2024.
3. IBM Quantum — Understanding Quantum Circuits and Gate Types. https://docs.quantum.ibm.com/build/circuit-library

---

### QTT017 — Credential Exposure

| Field | Value |
|---|---|
| **Technique ID** | `QTT017` |
| **Technique Name** | Credential Exposure |
| **Detection Rule** | `RULE_001_credential_leak_github_search` |
| **Severity** | Critical |
| **MITRE ATT&CK Mapping** | TA0006 Credential Access → T1552.001 Credentials in Files |
| **Visual Effect** | Particle Leak (red particles escaping) |

#### Description

Credential exposure detects quantum platform API tokens that have been inadvertently published in public code repositories, notebooks, documentation, or configuration files. IBM Quantum, for example, uses `QiskitRuntimeService(token="...")` patterns for authentication, and these tokens are frequently committed to GitHub repositories by researchers and students. Exposed tokens provide direct, authenticated access to the quantum platform with all the permissions of the original owner, enabling job submission, data retrieval, and potentially administrative operations.

#### Real-World Applicability

This is the most common and most impactful threat to quantum cloud users today. A GitHub search for "QiskitRuntimeService(token=" returns thousands of results, many containing valid tokens. Once exposed, these tokens can be harvested by automated bots scanning public repositories. The consequences include unauthorized consumption of quantum compute allocation, theft of quantum research results, and potential access to other resources if tokens are reused across services.

#### Detection Methodology

QVis integrates with the GitHub Code Search API to scan for exposed quantum platform tokens. The rule filters for patterns containing `token=` while excluding obvious placeholders (`YOUR_TOKEN`, `PLACEHOLDER`). Detected tokens are reported as critical-severity events with repository, file, and line number evidence.

```python
if 'token=' in pattern and 'YOUR_TOKEN' not in pattern and 'PLACEHOLDER' not in pattern.upper():
```

#### False Positive Considerations

- **Tutorial repositories**: Many tutorials intentionally include example tokens, though these should be placeholders.
- **Test fixtures**: CI/CD pipelines may include test tokens that are auto-rotated.
- **Revoked tokens**: Previously exposed and revoked tokens may still appear in search results.
- **Mitigation**: The explicit exclusion of common placeholder patterns (`YOUR_TOKEN`, `PLACEHOLDER`) eliminates most benign matches. Manual verification is required for confirmed positives.

#### References

1. MITRE ATT&CK, T1552.001 — Credentials in Files. https://attack.mitre.org/techniques/T1552/001/
2. GitGuardian, "State of Secrets Sprawl Report 2024." https://www.gitguardian.com/state-of-secrets-sprawl
3. GitHub Blog, "Token Scanning and Secret Scanning." https://github.blog/security/

---

### HEALTH — Hardware Degradation

| Field | Value |
|---|---|
| **Technique ID** | `HEALTH` |
| **Technique Name** | Hardware Degradation |
| **Detection Rule** | `RULE_008_backend_health_anomaly` |
| **Severity** | Info |
| **MITRE ATT&CK Mapping** | N/A (Infrastructure Health — not an attack technique) |
| **Visual Effect** | Calibration Drain (green funnel) |

#### Description

Hardware degradation monitoring tracks significant drops in qubit coherence times (T1 relaxation time) relative to an established baseline. When a qubit's T1 drops below 60% of its historical baseline value, QVis flags this as a health anomaly. While not a direct attack indicator, hardware degradation can be caused by adversarial activity (sustained abuse of specific qubits, deliberate circuit patterns causing crosstalk) and more commonly by natural decoherence, thermal fluctuations, or manufacturing defects. This monitoring is essential because degraded qubits produce unreliable results that can mask other security-relevant anomalies.

#### Real-World Applicability

Superconducting qubits are extremely sensitive to their environment. T1 times can vary significantly over hours to days due to temperature fluctuations, two-level system defects, and cosmic ray events. Monitoring these changes is critical for maintaining reliable quantum computation. Sudden or targeted degradation of specific qubits may also indicate adversarial interference, though this is currently theoretical.

#### Detection Methodology

QVis maintains a rolling baseline of qubit T1 coherence times. The rule compares each qubit's current T1 against its historical baseline and triggers when the current value falls below **60%** of the baseline. The baseline is updated continuously to adapt to gradual hardware changes while still detecting sudden drops.

```python
if curr_t1 < (base_t1 * 0.6):  # More than 40% drop from baseline
```

#### False Positive Considerations

- **Normal calibration cycles**: Backends undergo periodic recalibration which temporarily changes T1 values.
- **Seasonal/environmental variations**: Lab temperature changes can cause gradual T1 drift.
- **Mitigation**: The 60% threshold is aggressive enough to avoid false positives from normal calibration variance (typically <20%), while catching significant degradation events.

#### References

1. J. M. Gambetta et al., "Building a Software Ecosystem for Quantum Computing," *IBM Journal of R&D*, 2020.
2. M. R. Geller et al., "T1 and T2 Variability in Superconducting Qubits," *Physical Review Applied*, 2022.
3. IBM Quantum — Understanding Error Rates. https://docs.quantum.ibm.com/guides/understanding-error-metrics

---

## Correlation Patterns (Campaign Detection)

QVis includes a cross-rule correlation engine that detects **multi-stage attack campaigns** by identifying when two or more individual threat techniques co-occur on the same backend within a defined time window. When a correlation pattern is matched, a new campaign event is generated with escalated severity and additional context linking the constituent techniques.

Correlation events use technique IDs in the format `CORR:<backend_id>:<pattern_name>`.

---

### CORR — Coordinated Reconnaissance

| Field | Value |
|---|---|
| **Pattern Name** | Coordinated Reconnaissance |
| **Triggering Techniques** | QTT003 (Timing Oracle) + QTT002 (Calibration Harvesting) |
| **Time Window** | 30 minutes |
| **Escalated Severity** | Critical |

#### Description

This pattern detects when an adversary simultaneously conducts timing oracle attacks and calibration harvesting against the same quantum backend within a 30-minute window. The combination suggests a targeted QPU characterization campaign — the attacker is building a complete model of the backend's noise characteristics (via calibration harvesting) and operational timing (via timing oracle). Together, these provide the information needed to craft adversarial circuits optimized for the specific hardware configuration.

#### Detection Methodology

The correlator maintains a rolling history of threat events per backend. When both QTT003 and QTT009 events are detected on the same backend within 30 minutes, a campaign event is generated with severity escalated to Critical. Duplicate campaign events are suppressed using a deduplication key.

#### Remediation

1. Investigigate correlated activity as a coordinated campaign.
2. Review all involved techniques for a multi-stage attack.
3. Consider blocking the source if confirmed malicious.

---

### CORR — Pre-Attack Staging

| Field | Value |
|---|---|
| **Pattern Name** | Pre-Attack Staging |
| **Triggering Techniques** | QTT017 (Credential Exposure) + QTT003 (Timing Oracle) |
| **Time Window** | 60 minutes |
| **Escalated Severity** | Critical |

#### Description

This pattern detects when credential exposure is followed by timing oracle probes within a 60-minute window. This strongly suggests that an attacker has obtained leaked credentials and is actively using them to probe the quantum backend's timing characteristics. This is a "pre-attack staging" pattern because the credential compromise provides the access, and the timing oracle represents reconnaissance that typically precedes a more sophisticated attack using the compromised credentials.

#### Detection Methodology

The correlator monitors for QTT017 events followed by QTT003 events on the same backend within 60 minutes. The wider time window (compared to Coordinated Reconnaissance) accounts for the delay between credential harvesting and active exploitation. Severity is escalated to Critical.

#### Remediation

1. Investigate correlated activity as a coordinated campaign.
2. Review all involved techniques for a multi-stage attack.
3. Consider blocking the source if confirmed malicious.

---

### CORR — Enumeration Campaign

| Field | Value |
|---|---|
| **Pattern Name** | Enumeration Campaign |
| **Triggering Techniques** | QTT009 (Tenant Probing) + QTT011 (IP Extraction / IDOR) |
| **Time Window** | 15 minutes |
| **Escalated Severity** | Critical |

#### Description

This pattern detects when cross-tenant probing (QTT009) and large-scale IDOR enumeration (QTT011) co-occur on the same backend within 15 minutes. This indicates an active, systematic unauthorized access campaign — the attacker has moved from initial probing (testing a few job IDs) to large-scale enumeration (sweeping entire ID ranges). The short 15-minute window reflects the rapid escalation from reconnaissance to active exploitation.

#### Detection Methodology

The correlator triggers when both QTT009 and QTT011 are detected on the same backend within 15 minutes. This rapid escalation pattern warrants immediate investigation and potential automated blocking.

#### Remediation

1. Investigate correlated activity as a coordinated campaign.
2. Review all involved techniques for a multi-stage attack.
3. Consider blocking the source if confirmed malicious.

---

### CORR — Resource Abuse Chain

| Field | Value |
|---|---|
| **Pattern Name** | Resource Abuse Chain |
| **Triggering Techniques** | QTT008 (Resource Exhaustion) + QTT005 (Scope Violation) |
| **Time Window** | 30 minutes |
| **Escalated Severity** | High |

#### Description

This pattern detects when resource exhaustion (submitting near-max-depth circuits) is combined with privilege escalation attempts (token scope violations) within 30 minutes. This suggests an attacker who, having failed to escalate privileges (scope violations), pivots to a denial-of-service approach by consuming quantum resources. Alternatively, the resource exhaustion may be a diversion while privilege escalation attempts continue on other endpoints.

#### Detection Methodology

The correlator triggers when both QTT008 and QTT005 events are detected on the same backend within 30 minutes. The severity is escalated to High (not Critical, as resource abuse while disruptive, may not indicate data exfiltration).

#### Remediation

1. Investigate correlated activity as a coordinated campaign.
2. Review all involved techniques for a multi-stage attack.
3. Consider blocking the source if confirmed malicious.

---

## Summary Matrix

| Technique ID | Name | Severity | Rule | ATT&CK Tactic |
|---|---|---|---|---|
| QTT002 | Calibration Harvesting | Medium | RULE_002 | Credential Access |
| QTT003 | Timing Oracle | High | RULE_003 | Discovery |
| QTT005 | Scope Violation | High | RULE_007 | Initial Access |
| QTT008 | Resource Exhaustion | Medium | RULE_005 | Impact |
| QTT009 | Tenant Probing | High | RULE_004 | Discovery |
| QTT011 | IP Extraction | Critical | RULE_006 | Exfiltration |
| QTT012 | Multi-Backend Recon | High | RULE_009 | Discovery |
| QTT013 | Anomalous Circuit | Medium | RULE_010 | Collection |
| QTT017 | Credential Exposure | Critical | RULE_001 | Credential Access |
| HEALTH | Hardware Degradation | Info | RULE_008 | N/A |

| Correlation Pattern | Techniques | Window | Escalated Severity |
|---|---|---|---|
| Coordinated Reconnaissance | QTT003 + QTT002 | 30 min | Critical |
| Pre-Attack Staging | QTT017 + QTT003 | 60 min | Critical |
| Enumeration Campaign | QTT009 + QTT011 | 15 min | Critical |
| Resource Abuse Chain | QTT008 + QTT005 | 30 min | High |
