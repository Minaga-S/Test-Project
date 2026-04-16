# Development Lifecycle and Repository Evolution

## Purpose

This guide explains how the project evolved across the main repository and the local NmapLocalScanner companion repository.

It is written as a lifecycle reference, not a commit-by-commit changelog. The goal is to show the logic behind the codebase structure: why features were added in the order they were, why the scanner moved to a local companion app, and why the docs now describe the system as a layered, security-first workflow.

## How To Read This Project History

The commit history shows a repeating pattern:

1. Build the core workflow.
2. Add a user-facing feature.
3. Harden security and failure handling.
4. Polish the UI and navigation.
5. Document the behavior so the next change is easier.

That pattern appears in both repositories:
- The main repository focuses on the hotel cybersecurity application.
- The NmapLocalScanner repository focuses on the local companion app that performs private scans on the user’s own machine.

## Main Repository Evolution

### 1. Core application shape

The application started as a classic operational dashboard:
- users authenticate,
- register assets,
- report incidents,
- review risk,
- and inspect dashboard summaries.

That is why the current structure is layered into routes, controllers, services, models, and page-level frontend scripts.

### 2. Security-first refinement

The repository then moved into a long hardening phase:
- stronger authentication and session handling,
- rate limiting,
- request validation,
- safer frontend rendering,
- and reduced exposure of internal data.

That phase explains why the app now uses explicit validation at the backend boundary and why the frontend avoids rendering dynamic values directly without sanitizing them first.

### 3. Operational visibility

Once the core workflows were stable, the codebase added operational visibility:
- dashboard metrics,
- incident trends,
- risk distributions,
- asset vulnerability concentration,
- and audit logging for privileged users.

The current docs now treat those views as part of the product’s operating model, not as decorative UI.

### 4. Scanner integration

The next important step was the move from ad hoc scanning logic to a dedicated local scanner bridge:
- the frontend requests a scan through the backend bridge,
- the local companion app runs Nmap on the user’s machine,
- and the result is returned to the backend for enrichment.

This change is important because it keeps scanning local, private, and explicit. The backend validates target scope and the companion app refuses broad or unsafe behavior.

### 5. Documentation as part of the product

The later commits added more documentation because the system became more interconnected:
- authentication now has multiple flows,
- risk calculation is deterministic but informed by threat intelligence,
- CVE enrichment feeds both incident data and graphs,
- and the scanner requires a separate local companion app.

The docs therefore need to explain behavior, not just list files.

## NmapLocalScanner Evolution

The companion repository follows a narrower lifecycle.

### 1. Secure scaffold

The earliest scanner release established a localhost-only scanner companion:
- bind to `127.0.0.1`,
- allow only local/private scan targets,
- and upload scan results through a controlled bridge.

### 2. Deployment and origin hardening

Later commits expanded the security posture:
- CORS handling for local development and hosted UI origins,
- manual setup guidance for Nmap,
- and improved user instructions so the scanner could be used safely by non-experts.

### 3. Operator clarity

The scanner repository also grew better release and usage documentation:
- clear executable-first instructions,
- explicit Nmap setup helper mode,
- release checksum handling,
- and terminal visibility for troubleshooting.

That is why the main repository now describes the companion app as an intentional part of the system rather than an optional extra.

## Development Lifecycle In Practice

The project now follows a practical lifecycle for changes:

1. Define the workflow and its security boundaries.
2. Add or adjust backend validation and service logic.
3. Wire the frontend view or control.
4. Add scanner or enrichment integration if the feature depends on live host data.
5. Harden rendering, error handling, and permissions.
6. Update docs so the behavior is traceable.

This is the same pattern the recent commit history shows:
- feature additions for auth, scanner, and incident flows,
- fixes for pagination, menu visibility, and dashboard metrics,
- and repeated docs updates after the code settled.

## How The Scanner Fits The Product Lifecycle

The scanner is not a side project. It is the local execution layer for safe network enrichment.

### End-to-end flow

1. The user opens the frontend and triggers a scan-related workflow.
2. The backend creates a controlled local-scanner request.
3. The NmapLocalScanner app receives the request on localhost.
4. Nmap runs locally against a private or loopback target.
5. The companion app returns scan details to the backend.
6. The backend enriches the asset security context with:
   - open ports,
   - OS hints,
   - service data,
   - CPE data,
   - and CVE matches.
7. The incident, risk, and dashboard views consume that context.

### Why this design exists

- It keeps the scanning engine local.
- It avoids exposing raw Nmap execution to the browser.
- It lets the backend enforce target scope and validation.
- It gives the UI a consistent security-context payload.

## Where This Shows Up In The Codebase

- Backend validation and orchestration live in `backend/controllers` and `backend/services`.
- Security context assembly lives in `backend/services/assetSecurityContextService.js`.
- Threat and risk derivation live in `backend/services/threatClassificationService.js` and `backend/services/riskCalculationService.js`.
- Chart and dashboard rendering live in `frontend/js/dashboard.js` and `frontend/js/risk-analysis.js`.
- Local scanner UI and flow handling live in `frontend/js/settings.js`, `frontend/js/assets.js`, and incident-related page scripts.
- The scanner companion documentation lives in `NmapLocalScanner/README.md`.

## Related Reference Material

- [Calculation and Visualization Reference](../manuals/calculation-and-visualization-reference.md)
- [API Reference](../manuals/api-reference.md)
- [System Overview](../overview/system-overview.md)
- [NmapLocalScanner README](../../NmapLocalScanner/README.md)
