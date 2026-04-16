# Local Development Setup

## Goal

Run frontend and backend locally and verify authentication and API connectivity.

## Prerequisites

- Node.js 18+ and npm.
- MongoDB connection string (local instance or cloud cluster).
- Gemini API key if AI-backed analysis should work end-to-end.

## Step 1: Install dependencies

From repository root:

```bash
npm --prefix backend install
```

## Step 2: Configure environment variables

Create backend/.env with at least:

```env
PORT=5000
NODE_ENV=development
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=replace_with_strong_secret
JWT_EXPIRATION=24h
JWT_REFRESH_SECRET=replace_with_strong_refresh_secret
JWT_REFRESH_EXPIRATION=7d
CORS_ORIGIN=http://localhost:3000,http://127.0.0.1:3000
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-1.5-flash
GEMINI_MODEL_VERSION=v1beta
LOG_LEVEL=info
```

Notes:
- If GEMINI_API_KEY is missing, incident/threat AI analysis endpoints can fail.
- CORS_ORIGIN accepts comma-separated origins and is merged with built-in localhost defaults.

## Step 3: Start backend API

```bash
npm --prefix backend run dev
```

Expected checks:
- Backend responds at http://localhost:5000/health with status ok.
- On first startup, database seed creates test users if user collection is empty:
  - admin@test.com / Admin123456
  - staff@test.com / Staff123456

## Step 4: Serve frontend static files

From frontend directory, use any static server, for example:

```bash
npx serve -l tcp://127.0.0.1:3000 .
```

Open the served URL in browser.

## Optional: Run Local Scanner Companion

If you want live local scanner workflows:

```bash
cd NmapLocalScanner
npm install
npm run dev
```

Keep this process running while using local scanner features in the frontend.

## Step 5: Verify API base URL selection

The frontend uses frontend/js/api-client.js logic:
- host localhost or 127.0.0.1 -> http://localhost:5000/api
- any other host -> production API URL constant

Optional override in browser console:

```js
localStorage.setItem('apiBaseUrlOverride', 'http://localhost:5000/api')
```

## Step 6: Smoke test

1. Open login page.
2. Sign in with seeded user.
3. Create one asset.
4. Submit one incident tied to that asset.
5. Confirm dashboard metrics and recent incidents update.

## Common Issues and Fixes

- 401 Invalid or expired token:
  - Clear browser localStorage and log in again.
  - Ensure JWT_SECRET did not change while using an old token.

- CORS error from browser:
  - Add your frontend origin to CORS_ORIGIN in backend/.env.
  - Restart backend after env changes.

- Incident creation fails during AI analysis:
  - Verify GEMINI_API_KEY and internet access.
  - Confirm GEMINI_MODEL and GEMINI_MODEL_VERSION are valid.

- Login succeeds but some UI pages redirect unexpectedly:
  - Check localStorage accessToken and user values.
  - Ensure frontend serves all files from the same origin.
