# Exploration: Dependency Confusion / Namespace Hijacking Detection

## Overview
The goal here is to detect "Dependency Confusion" vulnerabilities, where an internal package name is registered on a public registry (like npm or PyPI) to hijack the build process.
## Implementation Strategy

### 1. Finding Manifests
Instead of a standalone scanner, I'm thinking of basing this off the existing `bruter` or `vcs` modules. When those modules find manifest files during their scans, they can pass the content to a new `DependencyConfusionDetector` module.

Target files I'm focusing on:
- `package.json` / `package-lock.json`
- `requirements.txt` / `pip.conf`
- `.npmrc`
- `pom.xml` (Maven)
- `go.mod` (Go)

### 2. Extracting and Verifying
The module will parse these manifests to pull out package names. Then, it will query public registry APIs to see if they're available:
- **npm**: `https://registry.npmjs.org/<package>`
- **PyPI**: `https://pypi.org/pypi/<package>/json`

If a package name is **not found** on the public registry, it's a potential internal package and a candidate for hijacking.

## High-Precision & False Positive Mitigation
To keep the findings actionable and avoid noise, I'm focusing on a few specific checks:

### Scope Verification
For scoped packages (like `@company/project`), we can't just assume it's vulnerable.
- We check if the scope (`@company`) is registered on the public registry.
- If the scope is **unregistered**, it's a high-risk finding because anyone could claim that namespace.

### Registry Config Analysis
Files like `.npmrc` or `pip.conf` tell us how the package manager is configured.
- If we find a `registry="..."` pointing to a private server, or an `extra-index-url` in pip, we can adjust the risk level. If the project is explicitly configured to use a private registry, it's likely set up safely.

### Filtering
I'll implement filters to ignore things that aren't vulnerable to this specific attack:
- Local file paths (e.g., `"file:../lib"`)
- Direct git repository URLs (`"git+https://..."`)
- Packages that are already registered on the public registry.