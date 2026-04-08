# Local Scanning Agent Setup

This document explains how to set up and run the local scanning agent for private network asset scanning on Render.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│ User's Browser (on Render Frontend)                         │
│  └─ Clicks "Run Live Scan" for private target (192.168.x.x) │
└────────────────────────┬────────────────────────────────────┘
                         │
                    HTTP Request
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│ Render Backend API                                          │
│  └─ Creates ScanJob record                                  │
│  └─ Returns jobId and "Pending" status                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ Frontend polls /api/agents/scan-status/:jobId
                         │
┌────────────────────────▼────────────────────────────────────┐
│ Local Scanning Agent (running on user's network)            │
│  └─ Polls /api/agents/pending-scans every 5 seconds         │
│  └─ Picks up ScanJob                                        │
│  └─ Runs nmap scan locally                                  │
│  └─ Uploads results to /api/agents/scan-results             │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **Node.js** 14+ installed
- **nmap** installed and accessible from PATH
  - Windows: `choco install nmap` (with Chocolatey) or download from https://nmap.org/download.html
  - macOS: `brew install nmap`
  - Linux: `apt-get install nmap` or `yum install nmap`

## Local Development Setup

### 1. Configure the Agent API Key

Edit `backend/.env`:

```env
AGENT_API_KEY=your-secure-agent-api-key-change-this
ENVIRONMENT=local
```

Change `your-secure-agent-api-key-change-this` to a random string (e.g., `super-secret-key-12345`).

### 2. Start the Backend

```bash
cd backend
npm install
npm start
```

### 3. Run the Local Agent

In a new terminal:

```bash
cd backend
BACKEND_URL=http://localhost:5000 \
AGENT_API_KEY=your-secure-agent-api-key-change-this \
npm run agent:start
```

Or for development with auto-reload:

```bash
BACKEND_URL=http://localhost:5000 \
AGENT_API_KEY=your-secure-agent-api-key-change-this \
npm run agent:dev
```

You should see output like:

```
🚀 Local Scanning Agent Started
   Backend: http://localhost:5000
   Agent ID: agent-1712345678901
   Poll Interval: 5000ms
```

### 4. Run Frontend

In another terminal:

```bash
cd frontend
npx serve .
```

## Production (Render) Setup

### 1. Generate a Secure Agent API Key

Generate a random secure key (or use an environment variable manager):

```bash
# macOS/Linux
openssl rand -hex 32

# Windows PowerShell
[System.Guid]::NewGuid().ToString().Replace("-", "").Substring(0, 32)
```

### 2. Set Environment Variable on Render

Access your Render dashboard:

1. Go to your **Backend Service**
2. Click **Environment**
3. Add new variable: `AGENT_API_KEY=<your-generated-key>`
4. Save and redeploy

### 3. Run Agent on Your Local Machine

#### Option A: Docker Container (Recommended)

Create `Dockerfile.agent` in your project root:

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install nmap
RUN apk add --no-cache nmap

COPY backend/package*.json ./backend/
RUN cd backend && npm install

COPY backend ./backend

WORKDIR /app/backend

CMD ["npm", "run", "agent:start"]
```

Build and run:

```bash
docker build -f Dockerfile.agent -t scan-agent .
docker run -d --name local-scan-agent --restart unless-stopped \
  -e BACKEND_URL=https://your-render-backend.onrender.com \
  -e AGENT_API_KEY=your-api-key \
   -e AGENT_ID=hotel-lan-agent-01 \
  scan-agent
```

Useful Docker commands:

```bash
docker logs -f local-scan-agent
docker stop local-scan-agent
docker rm local-scan-agent
```

#### Option B: Direct Node.js on Your Machine

```bash
cd backend
npm install

# Create a .env.agent file with:
# BACKEND_URL=https://your-render-backend.onrender.com
# AGENT_API_KEY=your-api-key

BACKEND_URL=https://your-render-backend.onrender.com \
AGENT_API_KEY=your-api-key \
npm run agent:start
```

The agent will now poll your Render backend and execute scans locally.

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://localhost:5000` | Backend API URL |
| `AGENT_API_KEY` | `default-dev-key` | ⚠️ API key for agent auth (must match AGENT_API_KEY in backend .env) |
| `AGENT_ID` | `agent-{timestamp}` | Unique agent identifier |
| `POLL_INTERVAL_MS` | `5000` | How often to poll for pending scans (milliseconds) |

## Testing the Agent

### 1. Start Backend & Agent

Follow steps 2-3 above.

### 2. Run Frontend

```bash
cd frontend
npx serve .
```

### 3. Create an Asset & Run Scan

1. Open frontend at `http://localhost:3000`
2. Go to Assets
3. Add a new asset with:
   - **Asset Name**: Test Server
   - **Scan Target**: `localhost` or a private IP on your network
   - **Ports**: `22,80,443` (or custom)
4. Click **Run Live Scan**
5. Monitor the agent terminal for scan execution

### 4. Check Agent Logs

You should see output like:

```
📋 Picked up 1 job(s)

🔍 Executing scan: <jobId>
   Target: localhost
   Ports: 22,80,443
   Running nmap: localhost:22,80,443
✅ Scan completed, uploading results...
   Results uploaded ✓
```

## Troubleshooting

### Agent can't connect to backend

```
❌ Authentication failed. Check AGENT_API_KEY.
```

**Solution**: Verify `AGENT_API_KEY` matches in both agent and backend .env

### No nmap found

```
Error: spawn nmap ENOENT
```

**Solution**: Verify nmap is installed and in PATH

```bash
# Check if nmap is installed
nmap -v

# If not found, install:
# Windows: choco install nmap
# macOS: brew install nmap
# Linux: apt-get install nmap
```

### Agent not picking up jobs

Check:
1. Backend is running
2. Frontend can send scan requests
3. Agent API key matches
4. Backend logs show scan job creation

Monitor backend logs:

```bash
# In backend terminal, should show similar to:
# Scan job queued: <jobId> for target <target>
```

### Frontend can't connect to backend

On Render, update `CORS_ORIGIN` env variable to include your frontend URL:

```
CORS_ORIGIN=https://your-frontend.onrender.com,https://your-user-frontend.github.io
```

## Architecture Diagram for UI Flow

1. **User submits scan** → Frontend sends to Backend
2. **Backend checks if production** → Creates ScanJob instead of running scan
3. **Frontend receives jobId** → Starts polling for status
4. **Agent polls backend** → Picks up pending job
5. **Agent runs nmap** → Uploads results
6. **Frontend displays results** → User sees scan complete with data

## Security Considerations

- **Agent API Key**: Keep this secret. Treat it like a password.
- **TLS/HTTPS**: Always use HTTPS for production
- **Network segmentation**: Agent should run on the same network as targets
- **Rate limiting**: Backend has rate limiting enabled (can be adjusted in middleware)

## Notes

- Agents are stateless and can be operated in parallel
- Multiple agents can serve the same backend
- Scan jobs timeout after 4 minutes of no results
- Results are cached in MongoDB for audit trail
