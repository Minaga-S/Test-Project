# Viva Role Preparation (Code Ownership Split)

Use this guide to prepare each member for source-code viva questions with clear ownership and deep follow-up readiness.

## Kevin (System Architect + Backend Developer)

### Primary ownership
- `/home/runner/work/Test-Project/Test-Project/backend/server.js`
- `/home/runner/work/Test-Project/Test-Project/docs/guides/architecture-and-request-flow.md`
- `/home/runner/work/Test-Project/Test-Project/backend/routes/*.js`
- `/home/runner/work/Test-Project/Test-Project/backend/controllers/incidentController.js`
- `/home/runner/work/Test-Project/Test-Project/backend/services/threatClassificationService.js`
- `/home/runner/work/Test-Project/Test-Project/backend/services/riskCalculationService.js`

### Must explain confidently
- Middleware order and why it matters (Helmet, rate limiter, CORS, body parsing, auth, validation, error handling).
- Route mounting and protected modules.
- Backend layering: route -> controller -> service -> model.
- Why enrichment happens during incident creation and not only during reporting reads.

### Likely grill question
**Q:** Why enrich incident data at write-time?  
**A:** The incident stores threat, risk, NIST mapping, and recommendations as a snapshot at creation time, so dashboards and reports read consistent precomputed analysis with lower recomputation cost.

---

## Pahan (Backend Developer + Security Controls)

### Primary ownership
- `/home/runner/work/Test-Project/Test-Project/backend/controllers/authController.js`
- `/home/runner/work/Test-Project/Test-Project/backend/routes/auth.js`
- `/home/runner/work/Test-Project/Test-Project/backend/middleware/auth.js`
- `/home/runner/work/Test-Project/Test-Project/backend/models/User.js`
- `/home/runner/work/Test-Project/Test-Project/backend/middleware/rateLimiter.js`
- `/home/runner/work/Test-Project/Test-Project/backend/routes/assets.js`
- `/home/runner/work/Test-Project/Test-Project/backend/routes/localScanner.js`
- `/home/runner/work/Test-Project/Test-Project/backend/services/nmapScanService.js`

### Must explain confidently
- Password policy enforcement (minimum 12 chars with complexity).
- JWT + refresh strategy and session invalidation with session versioning.
- Login lockout and password reset lockout behavior.
- 2FA, recovery codes, and security question recovery.
- Scan target hardening (private/local scope, subnet checks, bridge token flow, strict validation patterns).

### Likely grill question
**Q:** How do you prevent unsafe scanning?  
**A:** The API accepts only validated local/private scan targets, applies subnet restrictions when needed, issues expiring bridge tokens for scanner requests, and validates enrichment payload fields before persistence.

---

## Minaga (Frontend Developer + Backend Integration)

### Primary ownership
- `/home/runner/work/Test-Project/Test-Project/frontend/js/api-client.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/dashboard.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/incident-report.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/risk-analysis.js`

### Must explain confidently
- API base URL resolution for localhost vs production hostnames.
- Bearer token attachment and auth-free endpoint handling.
- 401 flow: refresh attempt, retry, then forced logout if invalid.
- Session inactivity and absolute timeout tracking.
- How frontend submits incident data and renders backend-returned analysis.

### Likely grill question
**Q:** How does incident reporting connect to backend intelligence?  
**A:** The page submits incident data via the API client, backend services perform classification/risk/NIST/recommendation analysis, and the frontend displays analysis and progress states based on the returned payload.

---

## Janindu and Chithara (Cybersecurity Analyst + Frontend Developer)

### Primary ownership
- `/home/runner/work/Test-Project/Test-Project/frontend/js/audit-logs.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/settings.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/utils.js`
- `/home/runner/work/Test-Project/Test-Project/frontend/js/risk-analysis.js`
- `/home/runner/work/Test-Project/Test-Project/backend/controllers/riskController.js`
- `/home/runner/work/Test-Project/Test-Project/backend/controllers/nistController.js`

### Must explain confidently
- Output escaping and safe rendering for audit log fields to reduce XSS risk.
- Security settings UX (2FA setup, status, disable flow).
- Scanner status and user-facing security posture indicators.
- Risk and compliance presentation flow from backend data to frontend visuals and export flows.

### Likely grill question
**Q:** How do frontend choices support security governance?  
**A:** The UI enforces authenticated flows, escapes server-provided text, provides audit filtering/export for traceability, and visualizes risk and security controls so users can make operational decisions quickly.

---

## Cross-team trick question (important)

Some docs mention admin-only audit access, but current implementation behavior is mostly per-user scoped with single-role normalization:
- `/home/runner/work/Test-Project/Test-Project/backend/models/User.js` normalizes users to `User` role defaults.
- `/home/runner/work/Test-Project/Test-Project/backend/controllers/auditLogController.js` filters by `actorUserId`.

If questioned, answer honestly: the current release is single-role with permission checks; stricter RBAC/admin separation is a future hardening enhancement.

---

## Fast rehearsal format (10 minutes each)

1. 60-second architecture summary in your own words.  
2. Walk through 2 key files you own.  
3. Answer 2 likely grill questions directly.  
4. State 1 known limitation and 1 planned improvement.
