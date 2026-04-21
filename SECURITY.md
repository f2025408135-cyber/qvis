# Security and Threat Model

## QVis Security Posture (10/10 Production Grade)

QVis employs a **Zero-Trust Architecture** secured-by-default to ensure that Quantum Threat Intelligence streams remain isolated, protected, and auditable.

### Key Security Features
1. **Immutable Audit Logging**: All API actions mutate through a Cryptographic Hash Chain recorded in PostgreSQL. Operations cannot be tampered with post-execution.
2. **AES-256 Field Encryption**: Any sensitive intelligence (such as API Keys, hardware metrics, tokens) are encrypted at rest using PBKDF2HMAC salted derivation keys on AES-256 (Fernet).
3. **Strict RBAC & JWT Rotations**: WebSockets and REST APIs require short-lived JSON Web Tokens specifying roles (`ADMIN`, `ANALYST`, `VIEWER`). IP lockouts occur after 5 failed authentication attempts automatically.
4. **Resilient Circuit Breakers**: All external API aggregators (IBM Quantum, GitHub, etc.) are wrapped in an asynchronous Circuit Breaker to prevent denial of service (DoS) and application layer resource exhaustion.
5. **Locked Supply Chains**: Dependencies are strictly pinned using SHA-256 cryptographic hashes checked during continuous integration pipelines via `pip-audit`.
