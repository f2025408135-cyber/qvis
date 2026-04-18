# QVis Threat Model

> **QVis Application Security Threat Model — v1.0**
>
> This document presents a formal threat model for the QVis Quantum Threat Topology Engine application itself, analyzing the security posture of the system that monitors quantum cloud platforms. It covers trust boundaries, data flows, asset inventory, threat actor profiles, STRIDE-based threat classification, risk assessment, and the security controls implemented across the production upgrade phases.

**Repository**: [https://github.com/f2025408135-cyber/qvis](https://github.com/f2025408135-cyber/qvis)
**Document Version**: 1.0
**Last Updated**: April 2026

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [System Overview](#2-system-overview)
3. [Trust Boundaries](#3-trust-boundaries)
4. [Data Flow Diagram](#4-data-flow-diagram)
5. [Asset Inventory](#5-asset-inventory)
6. [Threat Actor Profiles](#6-threat-actor-profiles)
7. [STRIDE Threat Analysis](#7-stride-threat-analysis)
8. [Attack Surface Enumeration](#8-attack-surface-enumeration)
9. [Security Controls Inventory](#9-security-controls-inventory)
10. [Risk Assessment Matrix](#10-risk-assessment-matrix)
11. [Threat Mitigation Verification](#11-threat-mitigation-verification)
12. [Residual Risks and Recommendations](#12-residual-risks-and-recommendations)
13. [References](#13-references)

---

## 1. Purpose and Scope

This threat model addresses the security of the **QVis application platform itself** — the web service, API layer, database, authentication system, and infrastructure that together form the quantum threat intelligence visualization engine. It does not catalog the quantum computing threats that QVis *detects* (that function is covered by the Q-ATT&CK framework in `quantum-threat-taxonomy.md`), but rather the classical and application-layer threats that could compromise the integrity, availability, or confidentiality of the QVis system.

The scope encompasses all components deployed as part of the QVis production architecture: the FastAPI backend, WebSocket server, PostgreSQL or SQLite database, Docker container, CI/CD pipeline, and the quantum platform collector integrations (IBM Quantum, Amazon Braket, Azure Quantum). External dependencies including GitHub Code Search API, STIX export endpoints, and any webhook integrations are also within scope.

The intended audience for this document includes security engineers reviewing the QVis deployment, DevOps engineers configuring the infrastructure, and development team members implementing new features who need to understand the security constraints of the system.

---

## 2. System Overview

QVis is a Python-based FastAPI application that continuously collects telemetry from quantum cloud platforms, analyzes it through 10 detection rules, correlates individual threats into campaign patterns, persists findings to a database, and broadcasts real-time updates to connected clients via WebSocket. The system runs as a single Docker container behind a reverse proxy, with optional Kubernetes deployment support through health probe endpoints.

The architecture follows a closed-loop pipeline with seven stages:

```
Collect → Analyze → Correlate → Baseline → Persist → Broadcast → Visualize
```

Each stage runs asynchronously within the event loop, coordinated by a simulation timer that fires every 30 seconds by default. The backend exposes a REST API for threat querying, STIX export, administrative functions, and health monitoring, alongside a WebSocket endpoint (`/ws`) for real-time streaming of threat snapshots to the 3D visualization frontend.

Key architectural components and their responsibilities:

**Backend (FastAPI)**: Handles HTTP routing, authentication, rate limiting, security headers, API endpoints, and WebSocket management. Runs on Uvicorn with ASGI.

**Threat Engine**: Pure-function detection rules (`RULE_001` through `RULE_010`) that analyze telemetry snapshots and produce `ThreatEvent` objects. No side effects, no I/O — fully deterministic and testable.

**Correlator**: Maintains a rolling history buffer and detects four campaign patterns by temporal co-occurrence of individual technique detections.

**Baseline Manager**: Tracks Exponential Moving Averages (EMA) and z-scores for hardware metrics, detecting statistical anomalies that rule-based analysis cannot capture.

**Storage Layer**: SQLAlchemy ORM with Alembic migrations, supporting both SQLite (development) and PostgreSQL (production). WAL mode for concurrent reads.

**Collectors**: Platform-specific telemetry collectors for IBM Quantum (Qiskit Runtime), Amazon Braket (boto3), and Azure Quantum, plus the GitHub Token Scanner.

**Export Module**: Converts threat events to STIX 2.1 bundles for SIEM integration with Microsoft Sentinel, Splunk, and Elastic Security.

---

## 3. Trust Boundaries

Trust boundaries define zones where the security assumptions change. Data crossing a trust boundary must be validated, authenticated, and authorized. The QVis system has six primary trust boundaries:

```
┌─────────────────────────────────────────────────────────────────────┐
│  ZONE 0: External Internet                                          │
│  (Threat Actors, Legitimate Users, Quantum Platform APIs)          │
│                                                                     │
│  ═══════════════════════ BOUNDARY 1: TLS / Reverse Proxy ═══════   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  ZONE 1: DMZ / Edge                                         │   │
│  │  (Nginx/Caddy, Security Headers, Rate Limiter)              │   │
│  │                                                             │   │
│  │  ═════════ BOUNDARY 2: API Key Auth ══════════════════      │   │
│  │                                                             │   │
│  │  ┌───────────────────────────────────────────────────────┐ │   │
│  │  │  ZONE 2: Application (FastAPI)                         │ │   │
│  │  │  (REST API, WebSocket, Business Logic)                 │ │   │
│  │  │                                                       │ │   │
│  │  │  ═══════ BOUNDARY 3: Input Validation ══════════      │ │   │
│  │  │                                                       │ │   │
│  │  │  ┌─────────────────────────────────────────────────┐ │ │   │
│  │  │  │  ZONE 3: Threat Engine                           │ │ │   │
│  │  │  │  (Detection Rules, Correlator, Baseline)         │ │ │   │
│  │  │  │                                                 │ │ │   │
│  │  │  │  ═══════ BOUNDARY 4: ORM / Data Access ════     │ │ │   │
│  │  │  │                                                 │ │ │   │
│  │  │  │  ┌───────────────────────────────────────────┐ │ │ │   │
│  │  │  │  │  ZONE 4: Database (SQLite/PostgreSQL)     │ │ │ │   │
│  │  │  │  │  (Threats, Correlations, Migrations)      │ │ │ │   │
│  │  │  │  └───────────────────────────────────────────┘ │ │ │   │
│  │  │  └─────────────────────────────────────────────────┘ │ │   │
│  │  └───────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ═══════════════ BOUNDARY 5: Outbound API Calls ═══════════════   │
│                                                                     │
│  ┌──────────────────────────┐  ┌────────────────────────────────┐  │
│  │  IBM Quantum API         │  │  GitHub Code Search API        │  │
│  │  Amazon Braket API       │  │  Slack/Discord Webhooks        │  │
│  │  Azure Quantum API       │  │  SIEM STIX Endpoints           │  │
│  └──────────────────────────┘  └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

**Boundary 1 (TLS / Reverse Proxy)**: Separates untrusted internet traffic from the application edge. All inbound traffic must pass through HTTPS termination. Security headers are applied at this layer by `SecurityHeadersMiddleware`, including Content-Security-Policy, HSTS, X-Content-Type-Options, and X-Frame-Options.

**Boundary 2 (API Key Authentication)**: Protects API endpoints from unauthorized access. The `verify_api_key` dependency enforces API key validation using SHA-256 hashed comparison with `secrets.compare_digest()` to prevent timing attacks. Authentication can be disabled via `auth_enabled=False` for development.

**Boundary 3 (Input Validation)**: FastAPI's Pydantic models provide automatic type checking and coercion on all request bodies and query parameters. Additional validation prevents SQL injection through parameterized queries, and the rate limiter validates client identifiers to prevent cache poisoning.

**Boundary 4 (ORM / Data Access)**: SQLAlchemy ORM with parameterized queries prevents SQL injection. Alembic manages schema migrations with versioned, reversible change sets. Direct SQL is never constructed from user input.

**Boundary 5 (Outbound API Calls)**: External API calls to quantum platforms and GitHub use official SDKs (Qiskit, boto3) with credential management via Pydantic `SecretStr` fields that are never logged or exposed via `repr()`.

---

## 4. Data Flow Diagram

The following diagram traces the primary data flows through the QVis system, identifying the data types, processing stages, and storage points at each step:

```
                          ┌──────────────────────────┐
                          │  Quantum Cloud Platforms  │
                          │  (IBM, Braket, Azure)     │
                          └────────────┬─────────────┘
                                       │ Telemetry (calibration,
                                       │ job history, backend props)
                                       ▼
┌──────────────┐       ┌──────────────────────────────┐
│  GitHub Code  │       │     Collector Layer           │
│  Search API   │──────▶│  (AggregatorCollector)        │
└──────────────┘       │  - IBMQuantumCollector        │
                        │  - BraketCollector            │
                        │  - AzureQuantumCollector      │
                        │  - GitHubTokenScanner         │
                        └──────────────┬───────────────┘
                                       │ SimulationSnapshot
                                       │ (Pydantic model)
                                       ▼
                        ┌──────────────────────────────┐
                        │     Threat Engine             │
                        │  - RULE_001 → RULE_010        │
                        │  - ThreatCorrelator           │
                        │  - BaselineManager            │
                        └──────┬───────────┬───────────┘
                               │           │
                               │ ThreatEvent│ CorrelationEvent
                               │ List       │ List
                               ▼           ▼
            ┌──────────────────────────────────────┐
            │     Persistence Layer                │
            │  SQLite (dev) / PostgreSQL (prod)    │
            │  - threat_events table               │
            │  - correlation_events table          │
            │  - Alembic version tracking           │
            └──────────────┬───────────────────────┘
                           │
              ┌────────────┼────────────────┐
              │            │                │
              ▼            ▼                ▼
    ┌──────────────┐ ┌──────────┐  ┌──────────────┐
    │  REST API     │ │ WebSocket│  │  STIX Export │
    │  /api/threats │ │  /ws     │  │  /api/stix   │
    │  /api/admin   │ │ (real-   │  │  (SIEM feed) │
    │  /api/health  │ │  time)   │  │              │
    └──────┬───────┘ └────┬─────┘  └──────┬───────┘
           │              │               │
           ▼              ▼               ▼
    ┌──────────────┐ ┌──────────┐  ┌──────────────┐
    │  Web Browser  │ │  Three.js│  │  SIEM Platform│
    │  / Admin      │ │  3D Viz  │  │  (Sentinel,  │
    │  Client       │ │  Client  │  │   Splunk)    │
    └──────────────┘ └──────────┘  └──────────────┘
```

**Sensitive data at each stage:**

- **Collector Layer**: API tokens for IBM Quantum (`ibm_quantum_token`), AWS (`aws_access_key_id`, `aws_secret_access_key`), and Azure (`azure_quantum_subscription_id`) are stored as `SecretStr` in configuration and never transmitted to clients.

- **Threat Engine**: Processes telemetry that may contain intellectual property (circuit specifications, measurement results from other tenants). Detection rules are pure functions with no persistence side effects.

- **Database**: Stores threat events (including evidence dictionaries that may reference external job IDs and API patterns), correlation events with campaign metadata, and Alembic migration history. No credentials are stored in the database.

- **API Responses**: Threat events are served with full evidence to authenticated clients. The STIX export includes technique IDs, severity, and timestamps but excludes source API tokens.

- **WebSocket**: Streams `SimulationSnapshot` objects containing backend topology, active threats, and entanglement pairs to all connected clients. No authentication on WebSocket in current implementation (documented as residual risk in Section 12).

---

## 5. Asset Inventory

### 5.1 Data Assets

| Asset | Classification | Storage | Sensitivity |
|-------|---------------|---------|-------------|
| Quantum Platform API Tokens | Secret | Environment variables / `.env` | Critical |
| Threat Event Database | Confidential | SQLite / PostgreSQL | High |
| Correlation Event Database | Confidential | SQLite / PostgreSQL | High |
| Baseline Metrics | Internal | In-memory (EMA) | Medium |
| Calibration Telemetry | Confidential | In-memory (ephemeral) | Medium |
| STIX Export Bundles | Confidential | In-memory (on-demand) | Medium |
| CI/CD Pipeline Secrets | Secret | GitHub Actions secrets | Critical |
| Docker Image | Internal | Container registry | Medium |
| Retention Policy Config | Internal | Database / Config | Low |

### 5.2 System Assets

| Asset | Classification | Criticality |
|-------|---------------|-------------|
| FastAPI Application Server | Critical infrastructure | High |
| Database (SQLite/PostgreSQL) | Data store | High |
| WebSocket Server | Real-time communication | High |
| Collector Integrations | Telemetry source | Medium |
| GitHub Token Scanner | Credential leak detection | High |
| Prometheus Metrics Endpoint | Observability | Medium |
| Health Check Endpoints | Availability monitoring | Medium |
| Docker Container | Deployment unit | Medium |
| CI/CD Pipeline | Quality assurance | Medium |

### 5.3 Operational Assets

| Asset | Classification | Sensitivity |
|-------|---------------|-------------|
| API Key for Client Auth | Secret | Critical |
| Slack/Discord Webhook URLs | Secret | High |
| Rate Limit Configuration | Internal | Low |
| Log Output (structlog) | Internal | Medium |
| Coverage Reports | Internal | Low |

---

## 6. Threat Actor Profiles

### 6.1 External Threat Actors

**Nation-State Quantum Adversary (APT-Q)**

A well-resourced adversary affiliated with a nation-state intelligence agency, motivated by stealing quantum computing research, proprietary algorithms, and cryptographic implementations. Capabilities include advanced persistent access to quantum platforms, custom exploitation tools, and patience for long-term campaigns. This actor targets the quantum platforms that QVis monitors and may also target QVis itself to understand what threat detection capabilities exist, thereby evading detection on the monitored platforms. Attack sophistication: Advanced. Typical objectives: Intelligence collection, competitive advantage, cryptographic advantage.

**Cybercriminal Quantum Token Harvester**

A financially motivated actor who systematically scans public repositories for exposed quantum platform API tokens, then uses stolen tokens to consume quantum compute allocation (which has real monetary value on paid plans) or to sell access on dark web marketplaces. This actor is automated, high-volume, and opportunistic. Attack sophistication: Low to Moderate. Typical objectives: Resource theft, credential resale.

**Quantum Research Competitor**

A corporate espionage actor affiliated with a competing quantum computing company or research organization. Motivated by understanding competitor research directions, benchmarking results, and algorithm implementations. This actor may attempt to access QVis data (which reveals what threats are being detected on shared quantum platforms) to infer competitor security posture and quantum algorithm development. Attack sophistication: Moderate. Typical objectives: Competitive intelligence, IP theft.

**Script Kiddie / Opportunistic Attacker**

An unsophisticated attacker running automated scanning tools (Nikto, dirb, SQLmap) against exposed web services. Not specifically targeting QVis but may discover it through port scanning, Shodan, or DNS enumeration. Attack sophistication: Low. Typical objectives: Defacement, botnet recruitment, challenge.

### 6.2 Internal Threat Actors

**Malicious Insider (Developer)**

A developer with repository access who intentionally introduces vulnerabilities, backdoors, or exfiltrates sensitive data. Has access to source code, CI/CD configuration, and potentially deployment credentials. Mitigated through code review, CODEOWNERS requirements, CI quality gates, and principle of least privilege for production credentials. Attack sophistication: High. Typical objectives: Sabotage, data theft, financial gain.

**Negligent Insider (Developer)**

A developer who accidentally commits secrets, introduces injection vulnerabilities, or misconfigures security settings without malicious intent. This is statistically the most likely source of security incidents. Mitigated through pre-commit hooks, CI pipeline automated checks (bandit SAST scanning, ruff linting), structured logging that avoids secret leakage, and `SecretStr` type enforcement in configuration. Attack sophistication: N/A. Typical objectives: None (accidental).

### 6.3 Supply Chain Threat Actor

An attacker who compromises a dependency in the QVis supply chain — either a Python package (PyPI), Docker base image, or CI/CD action — to inject malicious code into the build pipeline. This could result in backdoor installation, credential exfiltration, or supply chain attack propagation to downstream consumers of QVis. Attack sophistication: Advanced. Typical objectives: Supply chain compromise, widespread exploitation.

---

## 7. STRIDE Threat Analysis

The STRIDE model categorizes threats into six types: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. Each is analyzed below against the QVis application components.

### 7.1 Spoofing — T-S001 through T-S003

**T-S001: API Key Spoofing via Brute Force**

An attacker attempts to guess valid API keys by brute-forcing the `X-API-Key` header against protected endpoints. If authentication is enabled and a weak key is configured, the attacker gains full API access. The current implementation uses SHA-256 hashing with constant-time comparison (`secrets.compare_digest`), which prevents timing side-channel attacks but does not limit guessing attempts beyond the rate limiter. The rate limiter (default 60 requests per 60 seconds) provides some protection but is IP-based and can be circumvented through distributed attacks or IP rotation.

Mitigations: Rate limiting reduces brute force velocity. API keys should use high-entropy values (128+ bits). Account lockout after N failures is not currently implemented but would strengthen this control. Monitoring for repeated authentication failures via the `qvis_api_auth_failures_total` Prometheus counter provides detection capability.

**T-S002: WebSocket Connection Spoofing**

An unauthorized client connects to the `/ws` WebSocket endpoint to receive real-time threat intelligence data without authentication. The current implementation does not enforce authentication on WebSocket connections, meaning any client that can reach the endpoint receives all broadcast snapshots. This is the highest-priority spoofing risk because it exposes the complete threat intelligence picture, including detection capabilities, backend topology, and campaign correlation data.

Mitigations: Deploy WebSocket behind the same reverse proxy that terminates TLS. Network-level access controls (firewall rules, VPN requirement) restrict who can reach the endpoint. Application-layer WebSocket authentication (token validation on connection handshake) is recommended for future implementation.

**T-S003: JWT/Session Token Forgery**

If the authentication mechanism is extended to support JWT or session tokens (not currently implemented), forged tokens could grant unauthorized access. Since the current system uses static API keys only, this threat applies to future development. Pydantic's type validation on all inputs provides a baseline defense, but JWT-specific validation (signature verification, expiration checking, claim validation) would need to be added.

### 7.2 Tampering — T-T001 through T-T004

**T-T001: SQL Injection via API Parameters**

An attacker crafts malicious input in API query parameters (e.g., `/api/threats?search=...` or `/api/stix?limit=...`) to inject SQL into database queries. SQLAlchemy's parameterized queries and Pydantic type validation provide strong protection against this threat. All database operations use ORM methods with bound parameters rather than raw SQL string concatenation. The CI pipeline includes bandit SAST scanning which would detect raw SQL construction.

Mitigations: SQLAlchemy ORM parameterized queries (inherent protection). Pydantic type validation on all inputs (rejects non-integer limit values, sanitizes strings). Alembic migrations use declarative models rather than raw DDL. Bandit scanning in CI detects `mark_safe` and `execute` calls with string formatting.

**T-T002: Threat Data Manipulation via API**

An authenticated attacker (or attacker who bypassed authentication via T-S001) modifies threat data through API endpoints. The current API design is primarily read-oriented for threat data — there is no PUT/PATCH endpoint for threat events. However, the admin API includes `POST /api/admin/retention/cleanup` which triggers database cleanup operations. If an attacker can reach this endpoint, they could force premature deletion of threat data, destroying forensic evidence.

Mitigations: Admin endpoints are protected by the same API key authentication. No write access to individual threat events exists in the API. Retention cleanup is idempotent and only affects resolved events (those with `resolved_at` set). Audit logging of admin operations would strengthen forensic capability.

**T-T003: Correlation Engine Data Poisoning**

An attacker who can influence the telemetry data flowing into the threat engine could manipulate detection outcomes. For example, injecting fake calibration data could trigger false calibration harvesting alerts (QTT002), or submitting specially crafted circuit data could suppress legitimate anomaly detection by shifting statistical baselines. This requires access to the collector layer, either by compromising quantum platform API responses (man-in-the-middle) or by exploiting the demo mode data injection path.

Mitigations: Collectors use official SDKs with TLS-encrypted connections to quantum platform APIs. Demo mode uses deterministic mock data that cannot be externally influenced. The BaselineManager includes a variance floor that prevents single outlier values from dramatically shifting baselines. A warmup period of 3 samples prevents immediate poisoning.

**T-T004: Log Injection via Structured Logging**

An attacker includes malicious strings in API inputs (e.g., user agent, request body) that are later included in structured log entries, potentially causing log injection or log forging. The structlog processor chain includes exception rendering and formatting, but does not explicitly sanitize input values before logging.

Mitigations: structlog outputs to JSON format (when `log_format=json`), which escapes control characters. Console format outputs are text-based but do not execute injected content. Log storage systems (ELK, CloudWatch) typically handle escaped content safely. Input length limits on API parameters prevent excessively large log entries.

### 7.3 Repudiation — T-R001 through T-R002

**T-R001: Unauthenticated Admin Actions**

If an attacker performs destructive admin actions (e.g., triggering retention cleanup, deleting data) through the API, the current logging may not provide sufficient forensic evidence to identify the actor. The structlog system records events with timestamps and context variables, but does not log the authenticated identity (API key hash) or client IP on every admin request.

Mitigations: Enhance logging for admin endpoints to include authenticated identity and client IP on every request. The `X-Forwarded-For` header (set by reverse proxy) should be logged. API access logs with response status codes provide a basic audit trail. Implementing a dedicated audit log table with immutable entries would strengthen non-repudiation.

**T-R002: WebSocket Event Repudiation**

WebSocket broadcast events are not logged individually, making it impossible to prove what data was transmitted to which client at what time. If a client claims they received (or did not receive) a specific threat notification, there is no server-side record to verify the claim.

Mitigations: Add WebSocket connection/disconnection logging (already partially implemented via `qvis_websocket_connections_active` metric). Implement per-message audit logging for high-severity threat broadcasts. Consider adding sequence numbers to WebSocket frames for completeness verification.

### 7.4 Information Disclosure — T-I001 through T-I005

**T-I001: API Token Exposure via Structured Logging**

The `Settings` class uses Pydantic `SecretStr` for all sensitive configuration values (`ibm_quantum_token`, `aws_access_key_id`, `aws_secret_access_key`, `api_key`, `github_token`, webhook URLs). The custom `__repr__` method only exposes non-sensitive fields. However, if a developer inadvertently uses `str(settings.ibm_quantum_token)` or `settings.ibm_quantum_token.get_secret_value()` in a debug log statement, the secret would appear in log output.

Mitigations: `SecretStr` type ensures `repr()` and `str()` return `***REDACTED***`. The `extra="forbid"` setting on `BaseSettings` prevents accidental addition of new fields that might not be properly wrapped. Developer education and code review catch accidental `get_secret_value()` usage. Bandit's B105 check detects hardcoded password strings.

**T-I002: Database Credential Exposure**

The `database_url` configuration field contains the full connection string including username and password for PostgreSQL deployments (e.g., `postgresql+asyncpg://user:password@host:5432/db`). This field is a plain string, not a `SecretStr`, meaning it could appear in debug output, error messages, or stack traces. If the application crashes with an unhandled exception in a database operation, the connection string might appear in the traceback.

Mitigations: Mark `database_url` as `SecretStr` in future versions. Ensure the structlog exception renderer truncates or redacts database connection strings. Store database credentials separately from the connection string (individual `db_user`, `db_password` fields as `SecretStr`). Configure the reverse proxy to suppress detailed error responses.

**T-I003: Threat Intelligence Disclosure via Unauthenticated Access**

If `auth_enabled=False` (the default), all API endpoints including `/api/threats`, `/api/stix`, and `/api/admin/retention` are accessible without authentication. This exposes the complete threat intelligence picture, including what threats are being monitored, what quantum platforms are being tracked, and the detection thresholds being used. An adversary could use this information to calibrate their attacks to stay below detection thresholds.

Mitigations: Enable `auth_enabled=True` in production deployments. Use the API key authentication for all external-facing endpoints. Network-level isolation (VPC, firewall) provides defense in depth. The Dockerfile should not expose the application directly to the public internet without a reverse proxy.

**T-I004: Prometheus Metrics Information Leakage**

The `/metrics` endpoint exposes internal operational metrics including `qvis_simulation_loop_duration_seconds` (revealing system performance), `qvis_threats_active` (revealing current threat levels), and `qvis_websocket_connections_active` (revealing user activity). While these metrics do not contain secrets, they provide an adversary with intelligence about system operations and current threat posture.

Mitigations: Scope the `/metrics` endpoint to internal network access only. Configure the reverse proxy to block external access to `/metrics`. Use Prometheus authentication (bearer token) if metrics contain sensitive information. Document which metrics are safe for external consumption.

**T-I005: Error Message Information Disclosure**

FastAPI's default error handling returns detailed validation error messages that include field names, expected types, and actual values. Python tracebacks (if debug mode is enabled) could expose internal file paths, library versions, and code structure. The `SecurityHeadersMiddleware` adds `nosniff` but does not suppress error details.

Mitigations: Disable FastAPI debug mode in production (`docs_url=None`, `redoc_url=None`). Use custom exception handlers that return generic error messages to external clients while logging detailed information server-side. The rate limiter already returns generic 400/429 responses without exposing internal state.

### 7.5 Denial of Service — T-D001 through T-D004

**T-D001: API Rate Limit Evasion**

An attacker circumvents the sliding-window rate limiter by distributing requests across multiple IP addresses (botnet) or by exploiting the window boundary timing. The current rate limiter tracks up to 10,000 IPs with 3 windows per IP, and prunes stale entries every 100 requests. A distributed attack with >10,000 unique IPs could exhaust the rate limiter's memory tracking capacity, causing legitimate IPs to be evicted and their rate limits reset.

Mitigations: The `_MAX_TRACKED_IPS` cap (10,000) prevents unbounded memory growth. Pruning evicts stale IPs based on window recency. The weighted sliding window algorithm prevents burst attacks at window boundaries. For production, consider adding an application-layer WAF (e.g., Cloudflare) for volumetric DDoS protection. Connection limiting at the reverse proxy level provides additional defense.

**T-D002: Database Exhaustion via Retention Bypass**

An attacker who can influence threat detection (e.g., by manipulating quantum platform telemetry, if they have access to a monitored backend) could generate a high volume of threat events that fill the database. While the retention policy automatically purges events older than 90 days, a sustained campaign generating thousands of events per day could exhaust storage before the retention window expires.

Mitigations: The retention policy engine purges resolved events at configurable intervals (default hourly). SQLite VACUUM reclaims disk space after cleanup. PostgreSQL uses autovacuum. The deduplication logic in the analyzer prevents duplicate threat events from being persisted. Rate limiting on the collection interval (30-second minimum) bounds event generation velocity. The admin API allows manual cleanup triggers and monitoring of database size.

**T-D003: WebSocket Connection Exhaustion**

An attacker opens a large number of WebSocket connections to `/ws`, consuming server resources (memory per connection, event loop capacity). WebSocket connections are long-lived and do not benefit from HTTP-level rate limiting. Each connected client receives broadcast messages, so N connections multiply the broadcast cost by N.

Mitigations: The `qvis_websocket_connections_active` Prometheus metric monitors connection count. A connection limit (max concurrent WebSocket connections) is recommended for production deployment. Reverse proxy connection limits (e.g., Nginx `limit_conn`) provide infrastructure-level protection. Connection timeout (idle timeout) should be configured to close stale connections.

**T-D004: Simulation Loop Starvation**

If database operations, external API calls, or WebSocket broadcasts become slow, the simulation loop's 30-second cycle time could be exceeded, causing backlog accumulation and eventual timeout. The Prometheus histogram `qvis_simulation_loop_duration_seconds` monitors cycle latency, but no automatic corrective action is taken when latency exceeds the interval.

Mitigations: The `--timeout=120` on pytest tests ensures individual operations are bounded. The async architecture prevents I/O from blocking the event loop. Database operations use connection pooling (SQLAlchemy). The collector layer has degraded mode fallbacks when external APIs are unreachable. Setting alerts on simulation loop duration exceeding 25 seconds (approaching the 30-second interval) enables proactive intervention.

### 7.6 Elevation of Privilege — T-E001 through T-E003

**T-E001: API Key to Admin Escalation**

If a user with a low-privilege API key (if role-based access is implemented in the future) accesses admin endpoints, they could perform administrative operations beyond their authorized scope. The current implementation uses a single API key with no role differentiation — the key is either valid (full access) or invalid (no access). This flat authorization model means any valid key grants access to all endpoints including admin functions.

Mitigations: The single-key model is simple but provides no granularity. For multi-user deployments, implement role-based access control (RBAC) with separate reader, analyst, and admin roles. The FastAPI dependency injection system supports per-endpoint authorization decorators. The CODEOWNERS file ensures PR reviews for security-sensitive code changes.

**T-E002: Demo Mode to Production Escalation**

The `DEMO_MODE=true` environment variable enables mock data and relaxed security checks. If this variable is accidentally set in a production deployment, the system would operate with simulated data rather than real quantum platform telemetry, providing a false sense of security. More critically, if `auth_enabled` and `demo_mode` are not properly configured together, the system could run without authentication while claiming to be in production mode.

Mitigations: The CI pipeline sets `DEMO_MODE=true` and `USE_MOCK=true` as global environment variables, ensuring test environments are clearly demarcated. The Dockerfile should validate configuration at startup and refuse to run with contradictory settings (e.g., production database URL with demo mode enabled). Health check endpoints provide environment status visibility.

**T-E003: Container Escape via Docker**

If the Docker container is misconfigured (e.g., running as root, with excessive capabilities, or with sensitive host paths mounted), an attacker who gains code execution inside the container could escalate to host-level access. The Dockerfile should follow container security best practices: non-root user, minimal capabilities, read-only filesystem where possible.

Mitigations: The Dockerfile should use a multi-stage build to minimize the attack surface. Run the application as a non-root user inside the container. Avoid mounting host paths into the container. Use Docker's `--read-only` flag for immutable filesystem. The CI pipeline includes Docker build validation as part of the merge gate.

---

## 8. Attack Surface Enumeration

### 8.1 Network Attack Surface

| Endpoint | Protocol | Auth Required | Purpose | Risk Level |
|----------|----------|---------------|---------|------------|
| `:8000/api/threats` | HTTPS | Optional (API key) | Threat query API | Medium |
| `:8000/api/threats/{id}` | HTTPS | Optional (API key) | Single threat detail | Medium |
| `:8000/api/stix` | HTTPS | Optional (API key) | STIX 2.1 export | Medium |
| `:8000/api/health` | HTTPS | None | Health status | Low |
| `:8000/api/health/ready` | HTTPS | None | Readiness probe | Low |
| `:8000/api/health/live` | HTTPS | None | Liveness probe | Low |
| `:8000/api/health/started` | HTTPS | None | Startup probe | Low |
| `:8000/api/admin/retention` | HTTPS | Optional (API key) | Retention stats | High |
| `:8000/api/admin/retention/cleanup` | HTTPS | Optional (API key) | Manual cleanup | High |
| `:8000/ws` | WSS | None | Real-time WebSocket | High |
| `:8000/metrics` | HTTPS | None | Prometheus metrics | Medium |
| `:8000/docs` | HTTPS | None | Swagger UI | Low |

### 8.2 Outbound Network Dependencies

| Destination | Protocol | Purpose | Risk if Compromised |
|-------------|----------|---------|-------------------|
| IBM Quantum API | HTTPS | Telemetry collection | Data poisoning |
| Amazon Braket API | HTTPS | Telemetry collection | Data poisoning |
| Azure Quantum API | HTTPS | Telemetry collection | Data poisoning |
| GitHub Code Search API | HTTPS | Token scanning | Intelligence disclosure |
| Slack/Discord Webhooks | HTTPS | Alert notifications | Phishing, spam |
| SIEM STIX endpoints | HTTPS | Threat intelligence export | Data exfiltration |

### 8.3 Filesystem Attack Surface

| Path | Purpose | Risk if Modified |
|------|---------|-----------------|
| `/data/qvis.db` | SQLite database | Data integrity compromise |
| `.env` | Configuration secrets | Credential theft |
| `/alembic/versions/` | Migration scripts | Schema manipulation |
| `calibration_results.json` | Threshold calibration data | Detection evasion |

---

## 9. Security Controls Inventory

### 9.1 Authentication and Authorization

| Control | Implementation | Status | Coverage |
|---------|---------------|--------|----------|
| API Key Authentication | `verify_api_key` with SHA-256 + `secrets.compare_digest` | Implemented | All API endpoints (when enabled) |
| Auth Toggle | `auth_enabled` configuration flag | Implemented | Global setting |
| Secret Management | Pydantic `SecretStr` for all credentials | Implemented | All sensitive config fields |
| WebSocket Authentication | Not implemented | Gap | WebSocket endpoint |
| RBAC / Role-Based Access | Not implemented | Gap | Multi-user scenarios |

### 9.2 Input Validation and Sanitization

| Control | Implementation | Status | Coverage |
|---------|---------------|--------|----------|
| Pydantic Type Validation | FastAPI automatic request validation | Implemented | All API inputs |
| SQL Injection Prevention | SQLAlchemy ORM parameterized queries | Implemented | All database operations |
| Rate Limiting | Sliding-window rate limiter with IP tracking | Implemented | All `/api/` routes |
| Client ID Validation | `_is_safe_client_id` rejecting malformed IPs | Implemented | Rate limiter inputs |
| Content Security Policy | `SecurityHeadersMiddleware` CSP header | Implemented | All HTTP responses |
| File Upload Validation | No file upload endpoints exist | N/A | N/A |

### 9.3 Data Protection

| Control | Implementation | Status | Coverage |
|---------|---------------|--------|----------|
| TLS Enforcement | HSTS header with 1-year max-age | Implemented | All responses |
| Secret Redaction in Logs | `SecretStr` + custom `__repr__` | Implemented | All `Settings` fields |
| Database Encryption at Rest | Not implemented | Gap | SQLite/PostgreSQL |
| STIX Export Pagination | `limit` and `offset` parameters | Implemented | `/api/stix` |
| Differential Persistence | `_persisted_ids` prevents duplicate inserts | Implemented | Threat events |
| Data Retention Policy | Configurable TTL with automatic cleanup | Implemented | Threat and correlation events |

### 9.4 Monitoring and Detection

| Control | Implementation | Status | Coverage |
|---------|---------------|--------|----------|
| Structured Logging | 7-processor structlog chain with JSON output | Implemented | All application events |
| Prometheus Metrics | 20+ metrics across 8 categories | Implemented | System performance |
| Auth Failure Counter | `qvis_api_auth_failures_total` | Implemented | Authentication events |
| Rate Limit Tracking | `qvis_rate_limit_exceeded_total` | Implemented | Per-endpoint |
| Health Probes | Liveness, readiness, startup probes | Implemented | Kubernetes deployment |
| SAST Scanning | Bandit with `-ll` severity threshold | Implemented | CI pipeline |
| Dependency Audit | Safety CLI for vulnerability scanning | Implemented | CI pipeline |

### 9.5 Infrastructure Security

| Control | Implementation | Status | Coverage |
|---------|---------------|--------|----------|
| Docker Multi-Stage Build | Reduces final image attack surface | Implemented | Container |
| Non-Root Container User | Dockerfile USER directive | Partial | Container |
| CI Quality Gates | 5-job pipeline with merge gate | Implemented | Code changes |
| CODEOWNERS | Path-based review requirements | Implemented | Sensitive paths |
| Security Headers | 8 headers including HSTS, CSP, X-Frame-Options | Implemented | All responses |
| API Cache Control | `no-store, no-cache` for `/api/` routes | Implemented | API responses |

---

## 10. Risk Assessment Matrix

Each identified threat is assessed on two dimensions: **Likelihood** (how probable the threat is given current controls) and **Impact** (the potential damage if the threat materializes). The risk rating is the product: `Risk = Likelihood × Impact`.

### 10.1 Risk Rating Scale

| Rating | Likelihood | Impact | Description |
|--------|-----------|--------|-------------|
| Critical | 0.9-1.0 | 0.9-1.0 | Immediate action required |
| High | 0.6-0.8 | 0.7-0.9 | Priority remediation |
| Medium | 0.4-0.6 | 0.4-0.6 | Planned remediation |
| Low | 0.1-0.3 | 0.1-0.3 | Accept or monitor |

### 10.2 Risk Assessment Summary

| ID | Threat | Likelihood | Impact | Risk | Existing Controls |
|----|--------|-----------|--------|------|-----------------|
| T-S001 | API Key Brute Force | 0.3 | 0.8 | Medium | Rate limiting, SHA-256 hashing |
| T-S002 | WebSocket Spoofing | 0.7 | 0.8 | **High** | None (documented gap) |
| T-T001 | SQL Injection | 0.1 | 0.9 | Low | SQLAlchemy ORM, Pydantic |
| T-T002 | Admin API Abuse | 0.4 | 0.7 | Medium | API key auth, no write endpoints |
| T-T003 | Data Poisoning | 0.2 | 0.6 | Low | Official SDKs, TLS, demo mode isolation |
| T-I001 | Token Exposure via Logs | 0.2 | 0.9 | Low | SecretStr, redacted repr |
| T-I002 | Database URL Exposure | 0.4 | 0.8 | Medium | Plain string (documented gap) |
| T-I003 | Unauthenticated Access | 0.7 | 0.7 | **High** | `auth_enabled` toggle (default off) |
| T-I004 | Metrics Information Leak | 0.5 | 0.3 | Low | Network scoping recommended |
| T-D001 | Rate Limit Evasion | 0.4 | 0.6 | Medium | IP cap, pruning, WAF recommended |
| T-D002 | Database Exhaustion | 0.3 | 0.5 | Low | Retention policy, deduplication |
| T-D003 | WebSocket Connection Exhaustion | 0.5 | 0.6 | Medium | Connection limit recommended |
| T-D004 | Simulation Loop Starvation | 0.2 | 0.5 | Low | Async I/O, degraded mode, monitoring |
| T-E001 | Flat Authorization Model | 0.3 | 0.6 | Medium | Single-key model (documented gap) |
| T-E002 | Demo Mode Misconfiguration | 0.4 | 0.7 | Medium | CI env vars, health check visibility |
| T-E003 | Container Escape | 0.1 | 0.9 | Low | Docker best practices |

### 10.3 Risk Heat Map

```
Impact →    Low      Medium      High      Critical
Likelihood
────────────────────────────────────────────────────
High       │                    T-S002     │
           │                    T-I003     │
────────────────────────────────────────────────────
Medium     │  T-I004   T-T002   T-I002     │
           │  T-D004   T-T003   T-E002     │
           │           T-E001   T-D001     │
           │                    T-D003     │
────────────────────────────────────────────────────
Low        │  T-T001   T-D002              │
           │  T-I001                      │
           │  T-E003                      │
────────────────────────────────────────────────────
```

---

## 11. Threat Mitigation Verification

### 11.1 Automated Verification (CI Pipeline)

The CI pipeline provides automated verification of security controls on every code change:

| Verification | Tool | What It Checks |
|-------------|------|---------------|
| Code Quality | ruff (E, F, W rules) | Syntax errors, undefined variables, unused imports |
| Format Compliance | ruff format | Consistent code formatting |
| SAST Scanning | bandit (-ll severity) | Hardcoded passwords, SQL injection, insecure functions |
| Dependency Vulnerabilities | safety | Known CVEs in Python packages |
| Test Coverage | pytest-cov | Minimum coverage threshold on backend code |
| Workflow Integrity | test_ci.py (25 tests) | CI config structure, .gitignore patterns, CODEOWNERS |

### 11.2 Manual Verification Checklist

The following security tests should be performed manually or via penetration testing on each release:

- **Authentication Bypass**: Verify all protected endpoints return 401 without valid API key when `auth_enabled=True`
- **Rate Limit Enforcement**: Confirm 429 responses after exceeding the configured rate limit
- **SQL Injection**: Test common injection patterns (`' OR 1=1--`, `'; DROP TABLE--`) against all query parameters
- **WebSocket Security**: Verify that WebSocket connections can be established only by authorized clients (future requirement)
- **Security Headers**: Use securityheaders.com or equivalent to verify all headers are present and correctly configured
- **Error Handling**: Verify that detailed error messages are not returned to unauthenticated clients
- **Secret Management**: Confirm no secrets appear in log output, environment variable dumps, or debug endpoints
- **Container Security**: Verify the Docker container runs as a non-root user and has minimal capabilities

### 11.3 Test Coverage Summary

The test suite provides automated regression detection for security-relevant code:

- **Authentication tests** (`test_auth.py`): Verify API key validation, missing key rejection, invalid key rejection
- **Rate limiting tests** (`test_ratelimit.py`): Verify sliding window enforcement, 429 responses, IP validation
- **Security headers tests** (`test_security_headers.py`): Verify all 8 security headers on responses
- **Input validation tests** (scattered): Verify Pydantic model validation rejects malformed inputs
- **Storage tests** (`test_storage.py`, `test_alembic.py`): Verify parameterized queries, migration integrity

---

## 12. Residual Risks and Recommendations

### 12.1 High-Priority Residual Risks

**WebSocket Authentication Gap (T-S002)**

The `/ws` endpoint currently has no authentication mechanism. Any client that can reach the server can receive the complete real-time threat intelligence stream, including backend topology, active threats, campaign correlations, and detection capabilities. This is the most significant residual risk because the data disclosed could enable a sophisticated adversary to calibrate their quantum platform attacks to evade QVis detection.

Recommended actions: Implement WebSocket authentication via token validation on the connection handshake. Require the same API key as a query parameter (`/ws?token=...`) or as a Sec-WebSocket-Protocol header. Add connection rate limiting specific to the WebSocket endpoint.

**Unauthenticated Access by Default (T-I003)**

The `auth_enabled` configuration defaults to `False`, meaning a fresh deployment exposes all API endpoints without authentication. While this is convenient for development and demonstration, it creates a risk that production deployments may inadvertently operate without authentication.

Recommended actions: Change the default to `auth_enabled=True` and require explicit opt-out for development. Add a startup warning log when `auth_enabled=False` and `DEMO_MODE=False` (indicating a production deployment without authentication). Document the security implications clearly in the deployment guide.

### 12.2 Medium-Priority Improvements

**Database URL as SecretStr (T-I002)**

The `database_url` configuration field is a plain string that could appear in error messages, stack traces, or debug output. For PostgreSQL deployments, this exposes the database username and password.

Recommended actions: Change `database_url` to `SecretStr` type. Alternatively, split into separate `db_host`, `db_port`, `db_user`, `db_password` (all `SecretStr`) and `db_name` fields. Ensure structlog exception rendering does not include database connection strings.

**RBAC Implementation (T-E001)**

The flat single-key authorization model does not support multi-user deployments where different analysts need different access levels (read-only analysts vs. full admin access).

Recommended actions: Implement a simple RBAC model with at least two roles: `reader` (query threats, view health) and `admin` (retention management, system configuration). Store role assignments in the database. Add role validation middleware.

**WebSocket Connection Limits (T-D003)**

No maximum connection limit exists for WebSocket connections, making the server vulnerable to connection exhaustion attacks.

Recommended actions: Add a configurable `max_websocket_connections` setting (default 100). Reject new connections with HTTP 503 when the limit is reached. Log connection rejections for monitoring.

### 12.3 Low-Priority Future Work

**Encryption at Rest**

Database files (SQLite `.db` or PostgreSQL data directory) are not encrypted. An attacker with filesystem access could read all persisted threat events, correlation data, and migration history.

Recommended actions: For SQLite, use SQLCipher extension for transparent encryption. For PostgreSQL, enable Transparent Data Encryption (TDE) at the storage layer. Document the tradeoff between encryption overhead and data sensitivity.

**Audit Logging**

Current logging focuses on operational events. A dedicated immutable audit log for security-relevant actions (authentication successes/failures, admin operations, configuration changes) would strengthen forensic capability.

Recommended actions: Create an `audit_events` table with append-only writes. Log all authentication attempts, admin API calls, and configuration changes. Implement audit log query API for authorized users. Set retention period longer than threat data (e.g., 1 year).

**Supply Chain Security**

Python package dependencies are validated by `safety` for known CVEs, but there is no mechanism to verify package integrity or detect typosquatting attacks at install time.

Recommended actions: Pin all dependency versions in `requirements.txt` (already partially done). Add package hash verification via pip's `--require-hashes` mode. Consider using a private package registry (devpi, AWS CodeArtifact) for dependency caching and verification. Pin GitHub Actions by SHA commit hash rather than tag.

---

## 13. References

1. Microsoft. "STRIDE Threat Modeling." Microsoft Security Development Lifecycle. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool

2. OWASP Foundation. "OWASP Threat Modeling Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html

3. MITRE Corporation. "MITRE ATT&CK Framework." https://attack.mitre.org/

4. NIST. "SP 800-30 Rev. 1: Guide for Conducting Risk Assessments." https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final

5. OWASP Foundation. "OWASP API Security Top 10 — 2023." https://owasp.org/API-Security/

6. Shostack, A. *Threat Modeling: Designing for Security*. John Wiley and Sons, 2014.

7. CIS. "Docker Benchmark v2.0.0." Center for Internet Security. https://www.cisecurity.org/benchmark/docker

8. OASIS. "Structured Threat Information Expression (STIX) 2.1." https://oasis-tcs.github.io/cti-documentation/stix/

9. GitGuardian. "State of Secrets Sprawl Report 2024." https://www.gitguardian.com/state-of-secrets-sprawl

10. NIST. "SP 800-53 Rev. 5: Security and Privacy Controls." https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
