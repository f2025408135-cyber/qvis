# QVis Audit Logging Spec

## 1. Objective
QVis incorporates a `ImmutableAuditLog` designed to capture all mutating intelligence queries to ensure non-repudiation of internal SOC usage. 

## 2. Event Specification
Audit Events are serialized via JSON mapping mapping `timestamp`, `user`, `ip`, `resource_type`, `resource_id`, `status`, `before_state`, and `after_state`. 

## 3. Cryptographic Verification
Each log hashes itself and stores the `prev_hash` of the sequence behind it in a Merkle-like chain constraint. 

A verification function `audit_logger.verify_chain()` can be run via Admin pipelines to cryptographically assert that records have not been dropped, manipulated, or spliced.
