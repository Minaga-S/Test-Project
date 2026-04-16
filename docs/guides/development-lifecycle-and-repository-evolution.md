# Development Lifecycle and Repository Evolution

## Purpose

This guide documents the engineering thought process that can be inferred from commit history in both repositories:
- the main application repository,
- the NmapLocalScanner companion repository.

The goal is to explain what was implemented, what was fixed, what was changed, and why those changes happened in that order.

## Method Used For This Timeline

This document is based on dated commit history from both repositories.

Interpretation rules used here:
- "Implemented" means commits that add a new capability or workflow.
- "Fixed" means commits that stabilize behavior, security, or reliability.
- "Changed" means commits that refine UX, docs, policy, or architecture direction.

## High-Level Engineering Arc

Across both repositories, the lifecycle follows a consistent pattern:

1. Build a working security workflow.
2. Integrate scanner and enrichment data into incident analysis.
3. Stabilize reliability and reduce unsafe edge behavior.
4. Harden auth/session/security boundaries.
5. Improve UX and operator clarity.
6. Document the system so future changes remain coherent.

NmapLocalScanner is not the primary repository, but it is a necessary supporting track in phases 2 and 3.

## Commit-Informed Timeline (Main Repository)

### 2026-04-01: Risk analysis interaction stabilization

Implemented:
- Better desktop collapsible behavior in risk analysis views.

Fixed:
- Panel toggle behavior and cache-busting issues that prevented expected interaction updates.

Thought process:
- The team first made sure risk views were reliably interactive before adding heavier incident and scanner-linked features.

### 2026-04-04: Identity and access hardening + 2FA rollout

Implemented:
- TOTP 2FA flow (signup prompt and settings management).
- Role and department updates in user-facing flows.

Fixed:
- Hosted deployment edge cases in TOTP verification.
- Mobile alignment and layout consistency issues.

Changed:
- Documentation alignment around Gemini config references.

Thought process:
- Before expanding operational risk features, identity assurance and account governance were strengthened.

### 2026-04-06 to 2026-04-07: Scanner-to-incident pipeline implementation

Implemented:
- Asset scanning workflow.
- Incident threat analysis pipeline connected to scan data.
- NIST CVE pipeline integration.
- Incident deep-link and incident detail enrichment behavior.

Fixed:
- Live scan context consistency for incident analysis.
- CVE detail UX and deep-link modal behavior.

Thought process:
- This is the core transition from static incident reporting to evidence-backed incident analysis.
- The implementation quickly moved into stabilization once real scan context started affecting risk outputs.

### 2026-04-08: Hardening wave for scanner UX, frontend safety, and secrets

Implemented:
- 2FA UX polish and consistent skeleton loading.
- Live scan workflow modal and terminal-output guidance.
- Dashboard badge unification and criticality UX improvements.

Fixed:
- Scan propagation and enrichment fallback behavior.
- Product/OS field propagation issues.
- Session model simplification (remember-me flow removal).

Changed:
- Backend env secret tracking removed and local secret handling improved.

Thought process:
- After scanner + enrichment integration landed, a broad hardening pass reduced UI ambiguity, stale state drift, and secret-management risk.

### 2026-04-09: UX architecture refinement and policy tightening

Implemented:
- Terms and conditions flow across registration/settings.
- Unified incident scan and asset preview behavior.
- Accurate scan time estimation for user trust in long operations.

Fixed:
- Scan preview validation for CPE and field repopulation.
- Gemini fallback chain reliability and model compatibility.

Changed:
- Push-notification direction was introduced in one phase and then cleaned up/removed in later commits, indicating policy/UX reassessment.

Thought process:
- This phase shows active convergence: feature work continued, but unstable or confusing behavior was revised quickly to preserve operator confidence.

### 2026-04-10: Scanner architecture pivot and integration hardening

Implemented:
- Local scanner-first runtime behavior and status exposure in frontend.
- CVE-backed fallback mitigation strategy when AI output is weak.

Fixed:
- Local network and loopback fetch behavior (PNA and origin-related constraints).
- Render/local-subnet validation issues.

Changed:
- Legacy backend Nmap execution paths removed.
- Embedded scanner gitlink removed from parent repository.

Thought process:
- This is the clearest architecture decision point.
- Scanning responsibility was consolidated into the local companion model, reducing server-side scan ambiguity and clarifying trust boundaries.

### 2026-04-12 to 2026-04-13: Pre-deployment stabilization and operational polish

Implemented:
- Pre-deployment checklist and UI polish work.

Fixed:
- Dashboard metrics behavior.
- Pagination and audit-log behavior.

Changed:
- Documentation updates to match stabilized runtime behavior.

Thought process:
- The focus shifted from adding features to making behavior predictable under real operator workflows.

### 2026-04-14 to 2026-04-16: Security hardening, docs consolidation, and targeted fixes

Implemented:
- Security-question recovery and forgot-password refinements.
- Consolidated technical documentation references.

Fixed:
- npm vulnerability remediation for follow-redirects.
- Incident top pagination control wiring.
- Audit log menu visibility by user role.

Changed:
- Risk forecast feature removed.
- Documentation expanded to include calculation and visualization references.

Thought process:
- Late-phase work is exactly what mature projects should show: targeted vulnerability fixes, permission-scope cleanup, and improved internal documentation.

## Commit-Informed Timeline (NmapLocalScanner Repository)

NmapLocalScanner is a supporting repository, but it follows a clear lifecycle that mirrors main-repo needs.

### 2026-04-10: Foundation release sequence

Implemented:
- Secure companion scaffold for local scanning (v1.0.0).
- CORS expansion for LAN/hosted integration needs (v1.0.1).
- Manual Nmap setup helper mode and polished guidance (v1.0.2).

Thought process:
- The scanner was built for secure local execution first, then opened only enough for real deployment and user setup reliability.

### 2026-04-14: Operator clarity and packaging polish

Implemented/Changed:
- Exe-first instructions clarified.
- Release-note and checksum maintenance updates.
- Repository cleanup (release-note removal commit).

Thought process:
- Once functional stability was acceptable, operator onboarding and release hygiene became the primary maintenance concern.

## Integrated Thought Process Across Both Repositories

The combined history suggests this intent:

1. Keep scanning local and controlled.
2. Keep backend analysis deterministic where possible (risk formula, CVE-severity influence).
3. Keep AI as an enrichment layer, not an unchecked authority.
4. Keep frontend behavior explainable with visible states (skeletons, badges, status labels).
5. Keep security posture iterative, not one-time.
6. Keep docs synchronized with operational reality.

This is why recent docs now include both:
- a calculation/visualization reference,
- and this lifecycle narrative.

## Where NmapLocalScanner Fits (Supporting, Not Dominant)

NmapLocalScanner is intentionally a supporting subsystem:
- It does not replace backend logic.
- It supplies local scan evidence that the backend normalizes and enriches.
- It improves data quality for threat/risk classification while preserving local privacy boundaries.

In practice:
1. Frontend initiates scan-related workflow.
2. Backend issues controlled scanner request.
3. NmapLocalScanner executes locally.
4. Backend receives result and builds security context.
5. Threat/risk/recommendation layers consume that context.
6. Dashboard and risk views visualize the result.

## Related References

- [Calculation and Visualization Reference](../manuals/calculation-and-visualization-reference.md)
- [API Reference](../manuals/api-reference.md)
- [System Overview](../overview/system-overview.md)
- [NmapLocalScanner README](../../NmapLocalScanner/README.md)
