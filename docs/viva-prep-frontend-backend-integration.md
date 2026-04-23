# Viva Prep: Frontend Developer & Backend Integration Role

## Opening Statement (30–45 seconds)

> "I worked as the frontend developer with backend integration ownership. I connected our static multi-page UI to a secured Express + MongoDB API, implemented auth-aware client behavior, and made incident/risk workflows reliable, secure, and user-friendly."

---

## What I Delivered

- Built and maintained all page flows: login/signup, dashboard, assets, incident reporting, risk analysis, and settings.
- Centralized API integration in `frontend/js/api-client.js` — covers base URL resolution, auth header injection, token refresh flow, 401 handling, and error normalization.
- Integrated secure auth UX: 2FA login/setup, forgot/reset password with security questions, and recovery code options.
- Connected dashboard UI with backend metrics, charts, and recent-incidents APIs; improved loading and UX states (skeletons, live badge states).
- Supported the scanner-integrated incident pipeline — frontend triggers feed the backend analysis path for threat/risk/NIST/recommendations.
- Kept docs and in-app instructions aligned, especially for scanner onboarding.

---

## Architecture Line to Remember

> "Frontend pages call a shared API client; backend follows route → controller → service → model with middleware for auth, validation, rate limiting, and error handling."

```
Browser (HTML + CSS + JS)
  └── api-client.js   [central fetch layer, auth headers, error handling]
        └── Backend API (Express)
              └── Middleware: rateLimiter → authMiddleware → validateRequest → errorHandler
              └── Routes → Controllers → Services → Mongoose Models → MongoDB
                                          └── Gemini AI (threat/recommendation enrichment)
```

---

## Likely Viva Questions and Strong Answers

### Q: Why did you use a central API client?
**A:** To avoid duplicate fetch logic across page scripts, keep auth/session handling consistent in one place, and make future endpoint changes safer — you update one file, not many.

### Q: How do you handle expired access tokens?
**A:** On a 401 response from the backend, the client automatically attempts a token refresh once using the stored refresh token. If that also fails, it clears auth state from session/local storage and redirects the user to the login page. This prevents infinite loops.

### Q: How do frontend and backend stay aligned?
**A:** Through shared API contracts defined in the API reference docs, validation-aware error handling (field-level errors are merged into the UI message), and endpoint-level integration testing plus manual flow checks.

### Q: What security controls did you integrate on the frontend?
**A:** JWT auth headers on all protected calls, permission-gated route enforcement on the backend, session invalidation logic on password change, password strength policy UX with real-time guidance, full 2FA flows, and safe 401/403 error redirection paths.

### Q: What was a major integration challenge?
**A:** Keeping scanner/incident context consistent across the UI and the backend analysis pipeline. We solved it through normalized security context payloads and clearer workflow states — the backend treats persisted scan data as canonical while still accepting client-side enrichment for fresh findings.

### Q: How is data isolation handled between users?
**A:** The backend filters all domain reads and writes by the authenticated user's ID (`req.user.userId`), so one user can never access another user's assets, incidents, or risk records.

### Q: Why a static multi-page frontend instead of a React/Vue SPA?
**A:** Scope-fit and delivery speed. Module-based JavaScript still gave us clear code structure, and static hosting (GitHub Pages) simplified deployment without a build step or runtime dependency.

### Q: How did you ensure UX reliability?
**A:** Skeleton loaders for data-heavy views like the dashboard, explicit empty and error states across all pages, auth failure redirects, and resilient fallback behavior when optional services (like the local scanner) are unavailable.

### Q: How does the local scanner integrate with the frontend?
**A:** The frontend checks scanner reachability by pinging `http://127.0.0.1:47633/health` and reflects its status in the dashboard badge. When a scan is requested, the frontend sends the asset and target details to the backend `/api/local-scanner/requests` endpoint; results come back through `/api/local-scanner/results` and enrich the incident's security context automatically.

### Q: How does the incident analysis pipeline work end to end?
**A:** The frontend collects an asset ID, incident description, and optional scanner context. The backend controller validates ownership, runs threat classification via the AI service, calculates risk score and level, maps NIST controls, generates recommendations, and saves everything as one canonical incident record that dashboards and reports consume.

---

## Team Summary — "What We Did"

- Delivered a full cybersecurity governance workflow: **auth → assets → incidents → risk analysis → dashboard → audit logs**.
- Added and hardened **2FA setup, login verification, and multi-path account recovery** (TOTP, recovery codes, security questions).
- Integrated **local scanner-assisted enrichment** into the incident/risk processing pipeline.
- Improved deployment readiness and ensured documentation and in-app instructions stayed consistent.
- Performed stabilization and hardening passes covering security boundaries, UX clarity, and reliability.

---

## Recommended Demo Order

1. **Login / 2FA** — show login, optional 2FA prompt, redirect to dashboard.
2. **Dashboard metrics** — KPI cards, sparklines, live scanner badge, recent incidents table.
3. **Asset create/update** — register a new asset, show asset types and criticality fields.
4. **Report incident** — pick asset, write description, submit, and show the AI-generated threat/risk/NIST/recommendation output.
5. **Incident logs / status update** — find the incident, change status to InProgress/Resolved, add a note.
6. **Settings / scanner onboarding** — show 2FA management and local scanner setup commands with copy UX.

---

## Closing Statement

> "My role ensured users got a smooth, secure frontend while backend integration stayed consistent, validated, and production-oriented."
