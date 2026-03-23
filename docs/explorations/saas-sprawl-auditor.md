# Exploration: SaaS Sprawl & Portal Misconfiguration Auditor

## Overview
The goal is to detect misconfigurations in popular SaaS portals like Jira, Confluence, and Salesforce that lead to unauthenticated access to internal data, dashboards, or user tables. This module focuses on **authorization logic flaws** rather than software version vulnerabilities.

## Implementation Strategy

### 1. Triggering via Technology Tags
This module will be triggered by technology tags discovered by the `WebappIdentifier` (via Wappalyzer). When a target is tagged as "Jira", "Confluence", or "Salesforce", the auditor will initiate technology-specific permission probes.

### 2. Detection Methodology
The module will check for common "publicly accessible" misconfigurations:

- **Jira**:
    - **Unauthenticated Dashboard Access**: Checking if internal dashboards are set to "Public".
    - **User Enumeration**: Testing API endpoints that might leak the full user directory.
- **Confluence**:
    - **Unauthenticated Space Access**: Attempting to access common internal spaces or page trees that are accidentally shared.
- **Salesforce**:
    - **Aura/Visualforce Misconfigurations**: Probing for exposed endpoints that allow querying internal object data without authentication.

## High-Precision & False Positive Mitigation
SaaS portals often have complex permission models. The auditor will focus on **safe, non-destructive read actions** to verify exposure:

- **Metadata Verification**: Instead of pulling full records, the auditor will check if a query for "count" or "metadata" returns a successful response from a supposedly private object.
- **Known-Safe Probes**: Only well-documented endpoints and common misconfiguration patterns will be tested to avoid noise.

## Risk Assessment
- **High**: Unauthenticated access to internal documents, customer data, or full user directories.
- **Medium**: Access to internal project names, metadata, or organizational charts.
- **Info**: Identification of SaaS portals for asset mapping and Shadow IT discovery.
