# Last Deployment Checklist (Render Only)

Use this checklist before the final deployment.

## 1. Repository and Branch Safety
- Ensure `main` is up to date with the release commit.
- Ensure no local-only hotfixes exist (`git status` clean, `git log origin/main..main` empty).
- Tag the release commit if needed.

## 2. Secrets and Environment
- Confirm no real secrets are committed in tracked files.
- Set Render environment variables:
  - `NODE_ENV=production`
  - `HOST=0.0.0.0`
  - `PORT` (Render injects this automatically)
  - `MONGODB_URI`
  - `JWT_SECRET`
  - `JWT_REFRESH_SECRET`
  - `JWT_EXPIRATION`
  - `JWT_REFRESH_EXPIRATION`
  - `CORS_ORIGIN` (frontend origin)
  - `GEMINI_API_KEY` (if AI routes are used)
  - `GEMINI_MODEL`
  - `GEMINI_MODEL_VERSION`
- Rotate any previously exposed credentials.

## 3. Data and Account Policy
- Confirm there are no startup seed scripts in deployment path.
- Confirm no default user credentials are documented or shipped.
- Ensure first account provisioning is done via sign-up flow.
- Confirm user model is single-role (`User`) with user-level permissions only.

## 4. Security Controls
- Verify auth and password reset endpoints are rate-limited.
- Verify CORS only allows trusted frontend origins.
- Verify Helmet headers are enabled.
- Verify JWT token expiry and refresh flow are configured.
- Verify audit logs are user-scoped (no cross-user access).

## 5. Runtime and Health
- Verify backend health endpoint responds on Render.
- Verify frontend API base URL points to Render backend.
- Verify scanner bridge endpoint availability for supported clients.
- Verify database connectivity and basic CRUD for assets/incidents.

## 6. Functional Smoke Test
- Register a new account.
- Login and open dashboard.
- Create and edit an asset.
- Create an incident for that asset.
- Open audit logs page and confirm only current user logs are visible.
- Run local scanner flow and confirm scan result upload completes.

## 7. Observability and Recovery
- Verify logs are visible in Render dashboard.
- Verify 4xx and 5xx responses do not leak stack traces.
- Verify rollback plan exists (previous commit/tag to redeploy).

## 8. Post-Deploy Verification
- Re-run smoke test in production URL.
- Monitor error rate for first 30-60 minutes.
- Capture release notes and deployment timestamp.
