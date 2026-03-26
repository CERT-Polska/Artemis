# Exploration: DevOps, CI/CD & Container Registry Auditor

## Overview
The goal is to move beyond simple "Exposed Panel" detection and implement **Active Verification** for high-impact infrastructure tools like Jenkins, GitLab, ArgoCD, Nexus, and Harbor. This module will focus on confirming actual exploitability (e.g., unauthenticated file-read or container pull) to provide high-signal, actionable security findings.

## Implementation Strategy

### 1. Targeted Service Identification
Instead of running a broad set of scans on every target, this module will leverage an expanded `WebappIdentifier` to trigger specific auditor probes only when a relevant service is identified.

Target services and unique signatures:
- **Jenkins**: Detect via `X-Jenkins` headers or unique dashboard elements.
- **GitLab**: Detect via specific CSS hashes or login page signatures.
- **ArgoCD**: Detect via `http.title: "Argo CD"` or favicon hashes.
- **Nexus**: Detect via dashboard metadata and API signatures.
- **Harbor**: Detect via unique API endpoints (e.g., `/v2/_catalog`).

### 2. Active Verification Methodology
The module will utilize a hybrid approach of tool integration and custom logic:

- **Targeted Nuclei Integration**:
    - Trigger only service-specific templates (e.g., `CVE-2024-4956` for Nexus, `CVE-2024-23897` for Jenkins).
    - Ensure support for specialized Nuclei protocols (e.g., JavaScript protocol for Jenkins CLI flaws).
- **Custom Verification Probes**:
    - **Harbor/Docker Registry**: Perform a safe, unauthenticated `list/pull` of a manifest to confirm actual data exposure.
    - **ArgoCD**: Check for unauthenticated access to the Redis cache or API credential leaks (`CVE-2025-55190`).


### Confirmation-First Reporting
Findings will only be reported as "Interesting" if the active verification step confirms an insecure state. Simple "Panel Exposed" findings will be kept as low-severity or informational, depending on the environment.


## Risk Assessment
- **Critical**: Unauthenticated RCE or full administrative control (e.g., Jenkins Script Console, ArgoCD Cluster Admin).
- **High**: Unauthenticated arbitrary file read or sensitive credential leak (e.g., Nexus Path Traversal, GitLab Token Leak).
- **Medium**: Unauthenticated listing of internal project names or container images without full data access.
