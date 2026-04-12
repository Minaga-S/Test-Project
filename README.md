# Hotel Cybersecurity Governance System

## Overview
The Hotel Cybersecurity Governance System is a full-stack web application for managing hotel cybersecurity operations. It helps teams register digital assets, report incidents, assess risk, review audit activity, and track overall security posture through dashboard analytics.

The project is designed for practical day-to-day use by operations staff, IT/security teams, and management.

## Key Capabilities
- Authentication with token-based access control.
- Asset inventory management with vulnerability context fields.
- Incident reporting and incident lifecycle tracking.
- Risk analysis with threat classification and recommendations.
- Audit log query and export workflows.
- Dashboard metrics, trends, and summary insights.
- Local scanner integration route for controlled scanning workflows.

## Tech Stack
- Frontend: Static multi-page app (HTML, CSS, JavaScript modules).
- Backend: Node.js + Express.
- Database: MongoDB with Mongoose.
- Security: Helmet, CORS policy, JWT auth middleware, rate limiting, request validation.
- Testing: Jest + Supertest.

## Repository Structure
```text
backend/
	config/
	controllers/
	middleware/
	models/
	routes/
	services/
	utils/
frontend/
	css/
	js/
	*.html
```

## Local Development Setup

### Prerequisites
- Node.js 18+
- npm
- MongoDB instance

### 1) Start backend
```bash
cd backend
npm install
npm run dev
```

Backend defaults:
- Base URL: http://127.0.0.1:5000
- Health check: http://127.0.0.1:5000/health

### 2) Start frontend
```bash
cd frontend
npx serve -l tcp://127.0.0.1:3000 .
```

Open http://127.0.0.1:3000 in your browser.

### 3) API base behavior
- On localhost/127.0.0.1, frontend targets local backend API.
- On hosted origins, frontend targets production API.
- You can override API base URL using browser local storage key `apiBaseUrlOverride`.

## Backend Scripts
From backend/:

```bash
npm run dev
npm start
npm test
npm run seed:test-data
npm run reset:test-data
```

## Environment Variables
Typical backend environment values:

- NODE_ENV
- HOST
- PORT
- MONGODB_URI
- JWT_SECRET
- JWT_EXPIRATION
- JWT_REFRESH_SECRET
- JWT_REFRESH_EXPIRATION
- CORS_ORIGIN
- GEMINI_API_KEY
- GEMINI_MODEL
- GEMINI_MODEL_VERSION
- NMAP_SCAN_TIMEOUT_MS

Notes:
- CORS supports configured origins and selected local development origins.
- Scanner workflows are restricted to safe/local target categories by backend validation.

## API Surface (High Level)
Primary route groups:

- /api/auth
- /api/local-scanner
- /api/assets
- /api/incidents
- /api/threats
- /api/risk
- /api/nist
- /api/dashboard
- /api/audit-logs

Most route groups are protected by authentication middleware.

## Security and Governance
- Helmet headers enabled.
- Global API rate limiter enabled.
- Centralized error handling middleware.
- Request validation in middleware and route layers.
- Audit log reporting available via dedicated API and frontend page.

## Testing Guidance
- Backend tests are colocated with source modules as *.test.js.
- Use targeted test execution for faster feedback.

Examples:
```bash
cd backend
npm test
npm test -- backend/services/scanHistoryService.test.js
```

## Deployment Notes

### Frontend
- Static hosting compatible (for example GitHub Pages).

### Backend
- Node service hosting compatible (for example Render).
- Docker deployment is recommended when scanner features require nmap in runtime image.

## Default Seed Users
When seed scripts are enabled in your environment:

- admin@test.com / Admin123456
- staff@test.com / Staff123456

## Project Goals
- Improve cybersecurity visibility for hotel operations.
- Standardize incident and risk workflows.
- Provide management-ready insights without heavy technical overhead.

## License
MIT





