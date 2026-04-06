# Hotel Cybersecurity Governance System

## Executive Summary

The Hotel Cybersecurity Governance System is a web-based platform designed to help small and medium hotels manage cybersecurity risk in a practical, non-technical, and operationally useful way. It combines structured security workflows with AI-assisted analysis so hotel teams can report incidents, understand risk, and take corrective action without needing deep cybersecurity expertise.

This system is built to bridge the gap between day-to-day hotel operations and security governance by turning technical security events into clear decisions, dashboards, and follow-up actions.

## What This Website Is

This website is a cybersecurity operations and governance portal for hotels. It provides:

- a centralized interface for reporting and tracking incidents,
- an asset-oriented view of the organizationâ€™s digital exposure,
- risk scoring and prioritization,
- governance-aligned recommendations mapped to recognized security practices.

In short, it is a decision-support system for hotel cybersecurity management.

## What This Website Is For

The primary purpose of the platform is to enable hotels to:

1. Identify and register critical digital assets (systems, devices, applications).
2. Report security incidents in plain language.
3. Analyze incidents using AI-assisted classification and context.
4. Quantify risk to support prioritization and escalation.
5. Map findings to cybersecurity governance controls for remediation planning.
6. Monitor trends through dashboards for management-level visibility.

It is intentionally designed for environments where dedicated security teams may be limited, but accountability and risk visibility are still required.

## Target Users

### Operational Staff
- Report incidents quickly through simple forms.
- Capture observations without technical jargon.

### Security / IT Managers
- Review incident history, impact, and risk levels.
- Track patterns and recurring weaknesses.
- Use governance mappings to plan mitigation.

### Management / Decision Makers
- View concise risk indicators and trend dashboards.
- Prioritize remediation effort based on business impact.

## Core Functional Areas

### 1) Authentication and Access
- Secure user authentication using token-based access control.
- Role-oriented usage patterns for administrative and staff users.

### 2) Asset Management
- Inventory of hotel digital assets and their attributes.
- Foundation for asset-centric risk and incident analysis.

### 3) Incident Reporting and Tracking
- Structured incident capture and status progression.
- Searchable incident history and traceability.

### 4) AI-Assisted Threat and Risk Analysis
- Natural-language incident interpretation.
- Threat categorization and recommendation support.
- Risk level derivation for prioritization.

### 5) Dashboard and Governance Visibility
- High-level indicators for assets, incidents, and risk posture.
- Recent incident summaries and visual trend insights.

## Business Value

The platform delivers measurable value by:

- reducing response ambiguity with standardized incident handling,
- improving prioritization through consistent risk scoring,
- increasing governance readiness by aligning actions to control frameworks,
- giving leadership clear cybersecurity visibility for planning and accountability.

## System Architecture (High Level)

- Frontend: Static web client (HTML, CSS, JavaScript)
- Backend API: Node.js + Express
- Database: MongoDB
- Security: JWT authentication, password hashing, CORS controls, secure headers

The frontend provides user workflows and dashboards, while the backend enforces business logic, persistence, and protected API access.

## Current Deployment Model

This project is configured for hosted usage:

- Frontend hosted on GitHub Pages
- Backend hosted on Render

This separation supports simple static delivery for UI and scalable API hosting for application logic.

## Localhost Testing (Frontend + Backend)

Use this setup to test both layers locally.

### 1) Start the backend API

From `backend`:

```bash
npm install
npm run dev
```

Backend will run on `http://localhost:5000` and health check is `http://localhost:5000/health`.

### 2) Serve the frontend files locally

From `frontend`, run any static server. Example with Node:

```bash
npx serve .
```

Open the shown local URL (commonly `http://localhost:3000` or similar).

### 3) API routing behavior

- If frontend is opened from `localhost` or `127.0.0.1`, it uses `http://localhost:5000/api`.
- If frontend is opened from hosted domains, it uses the production API URL.

You can also force a custom API base URL by setting `localStorage.apiBaseUrlOverride` in the browser console.

## Setup and Deployment (Reference)

### Frontend Deployment

The repository includes a GitHub Actions workflow at `.github/workflows/deploy-frontend.yml` that deploys the `frontend` directory to GitHub Pages on pushes to `main`.

### Backend Deployment

The backend is designed to run as a Node.js web service (for example on Render). For Nmap support, deploy with Docker so the image includes the `nmap` binary. A production deployment requires:

- `MONGODB_URI`
- `JWT_SECRET`
- `JWT_EXPIRATION`
- `JWT_REFRESH_SECRET`
- `JWT_REFRESH_EXPIRATION`
- `GEMINI_API_KEY` (if AI endpoints are used)
- `GEMINI_MODEL`
- `GEMINI_MODEL_VERSION`
- `NMAP_SCAN_TIMEOUT_MS` (optional scan timeout override)

Nmap scans are restricted to localhost and private network targets only. Public IPs and public hostnames are rejected by the backend.

### Production API Endpoint

The frontend API base URL is configured in `frontend/js/api-client.js` via `PROD_API_BASE_URL` and must point to the deployed backend domain.

## CORS Configuration (Production)

Set `CORS_ORIGIN` to your hosted frontend origin, for example:

```env
CORS_ORIGIN=https://minaga-s.github.io
```

## Test Accounts

If database seeding is enabled, default test users are:

- `admin@test.com` / `Admin123456`
- `staff@test.com` / `Staff123456`

## Future Improvement Opportunities

- stronger role-based authorization boundaries,
- audit logs and action-level traceability,
- alerting and notification workflows,
- automated compliance reporting exports,
- extended analytics for trend forecasting.





