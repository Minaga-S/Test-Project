# Technical Documentation Hub

This documentation set follows a Diataxis-style structure and the principles from Bogdan Frankovskyi's framework:

- One document, one goal.
- Show, do not only tell (diagrams + examples).
- Be explicit about prerequisites and dependencies.
- Do not assume reader context.
- Cover gotchas and non-obvious behavior.

## Documentation Map

### Overview (context and orientation)
- [System Overview](overview/system-overview.md)

### Tutorials (step-by-step tasks)
- [Local Development Setup](tutorials/local-development.md)
- [Report Your First Incident End-to-End](tutorials/report-first-incident.md)

### Guides (learn concepts and patterns)
- [Architecture and Request Flow](guides/architecture-and-request-flow.md)
- [Security and Operations Gotchas](guides/security-and-operations-gotchas.md)

### Manuals / Reference (authoritative details)
- [API Reference](manuals/api-reference.md)
- [Data Model and Configuration Reference](manuals/data-model-reference.md)
- [Calculation and Visualization Reference](manuals/calculation-and-visualization-reference.md)
- [Technical Documentation (Professional Edition)](Hotel-Cybersecurity-Technical-Documentation-Professional.md)

## Current Implementation Notes

- The backend API includes local scanner bridge routes under `/api/local-scanner`.
- Authentication includes refresh tokens, 2FA flows, and security-question recovery support.
- Audit log read endpoints are available under `/api/audit-logs` for privileged users.
