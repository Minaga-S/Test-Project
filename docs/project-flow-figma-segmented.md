# Segmented Figma Diagrams (Copy-Ready)

Paste each Mermaid block into your Figma Mermaid plugin separately, then place all four on the same Figma page.

## Diagram 1: Executive Overview

~~~mermaid
flowchart LR
  U[Business User]
  FE[Frontend Experience\nPages + Forms + Dashboards]
  API[Backend API\nBusiness Rules and Security]
  DATA[(MongoDB Data Store)]
  AI[AI Analysis Service]
  OUT[Outputs\nRisk Scores, Recommendations, Reports]

  U --> FE --> API --> DATA
  API --> AI
  API --> OUT
~~~

## Diagram 2: Frontend Experience (What Users Touch)

~~~mermaid
flowchart TB
  subgraph PAGES[Pages Users Open]
    P1[index.html\nLogin and Signup]
    P2[dashboard.html\nKPIs and Overview]
    P3[report-incident.html\nReport New Incident]
    P4[incident-logs.html\nTrack and Update Incidents]
    P5[assets.html\nManage Company Assets]
    P6[risk-analysis.html\nRisk Charts and Reports]
    P7[settings.html\nAccount Settings]
    P8[faq.html, contact-support.html, user-guide.html\nHelp and Support]
  end

  subgraph SCRIPTS[Page Logic Files]
    S1[auth.js]
    S2[dashboard.js]
    S3[incident-report.js]
    S4[incident-logs.js]
    S5[assets.js]
    S6[risk-analysis.js]
    S7[settings.js]
  end

  SHARED[Shared Browser Logic\napi-client.js + utils.js]
  STYLE[Styling\nstyle.css + forms.css + dashboard.css + responsive.css]
  API2[Backend API Endpoints]

  P1 --> S1
  P2 --> S2
  P3 --> S3
  P4 --> S4
  P5 --> S5
  P6 --> S6
  P7 --> S7

  S1 --> SHARED
  S2 --> SHARED
  S3 --> SHARED
  S4 --> SHARED
  S5 --> SHARED
  S6 --> SHARED
  S7 --> SHARED

  PAGES -. visual design .-> STYLE
  SHARED --> API2
~~~

## Diagram 3: Backend Processing (How Decisions Are Made)

~~~mermaid
flowchart LR
  IN[Incoming API Request]

  subgraph SECURITY[Security and Validation]
    M1[rateLimiter.js\nControls abuse]
    M2[auth.js\nChecks login token]
    M3[validateRequest.js\nChecks input quality]
    M4[errorHandler.js\nStandard error output]
  end

  subgraph ROUTING[Route Groups]
    R1[auth routes]
    R2[asset routes]
    R3[incident routes]
    R4[threat routes]
    R5[risk routes]
    R6[nist routes]
    R7[dashboard routes]
  end

  subgraph APP[Application Logic]
    C[Controllers\nOrchestrate each API action]
    SV[Services\nThreat classification, risk math, recommendations, mappings]
  end

  DB[(MongoDB Models\nUser, Asset, Incident, Threat, RiskAssessment, AuditLog)]
  RESP[API Response to Frontend]

  IN --> SECURITY --> ROUTING --> C --> SV --> DB
  SV --> RESP
~~~

## Diagram 4: Data, Operations, and Delivery

~~~mermaid
flowchart TB
  subgraph CONFIG[Runtime Foundations]
    F1[server.js\nApp startup]
    F2[config/database.js\nDB connection]
    F3[config/ai-config.js\nAI setup]
    F4[utils/logger.js\nOperational logs]
    F5[scripts/seedDatabase.js\nInitial data and users]
  end

  subgraph DELIVERY[Delivery Pipeline]
    D1[Push to main branch]
    D2[.github/workflows/deploy-frontend.yml]
    D3[GitHub Pages deployment of frontend]
  end

  subgraph GOVERNANCE[Project Guidance]
    G1[README.md]
    G2[Daily summary files]
    G3[package.json and lock files]
  end

  F1 --> F2
  F1 --> F3
  F1 --> F4
  F1 --> F5

  D1 --> D2 --> D3

  G1 --> DELIVERY
  G2 --> DELIVERY
  G3 --> DELIVERY
~~~
