# Hotel Cybersecurity Governance System

AI-Assisted Cybersecurity Threat Assessment and Governance System for Small Hotels.

## Tech Stack

- Frontend: HTML, CSS, Vanilla JavaScript
- Backend: Node.js, Express, MongoDB
- Auth/Security: JWT, bcryptjs, helmet, cors

## Hosted Setup

This project is configured for hosted deployment only:

- Frontend: GitHub Pages
- Backend: Render

## Test Login Accounts

These users are seeded on backend start (if no users exist yet):

- `admin@test.com` / `Admin123456`
- `staff@test.com` / `Staff123456`

## Deploy Frontend to GitHub Pages

This repo includes a workflow at `.github/workflows/deploy-frontend.yml` that deploys the `frontend` folder to GitHub Pages when you push to `main`.

### First-time GitHub setup

1. Push this project to a GitHub repository.
2. In GitHub, open **Settings → Pages**.
3. Under **Build and deployment**, choose **Source: GitHub Actions**.
4. Push to `main` (or run the workflow manually from the Actions tab).

Your site will be published at:

`https://<your-username>.github.io/<your-repo>/`

## Important: Backend Cannot Be Hosted on GitHub Pages

GitHub Pages hosts only static frontend files. Your backend API must be hosted separately (for example Render, Railway, Fly.io, or any Node host).

After deploying backend, update this constant:

- File: `frontend/js/api-client.js`
- Constant: `PROD_API_BASE_URL`

Set it to your backend API URL, for example:

```js
const PROD_API_BASE_URL = 'https://your-backend-domain.com/api';
```

Then commit and push again so GitHub Pages uses the correct API endpoint.

## CORS for Production

In backend `.env`, include your GitHub Pages origin in `CORS_ORIGIN`, for example:

```env
CORS_ORIGIN=https://<your-username>.github.io
```

(If needed, include the repo path variant used by your deployment policy.)
