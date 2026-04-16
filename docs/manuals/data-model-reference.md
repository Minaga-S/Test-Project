# Data Model and Configuration Reference

## Purpose

Provide authoritative reference for persistent entities, constants, and runtime configuration.

## Core Entities

## User

Collection: users

Fields:
- email (unique, lowercase, required)
- password (hashed, min length 8)
- fullName (required)
- role (Admin or Staff)
- roles (derived array from role)
- permissions (derived from role)
- department (optional)
- isActive (default true)
- createdAt, updatedAt

Notes:
- Password is hashed in pre-save hook.
- JSON serialization omits password.

## Asset

Collection: assets

Key fields:
- assetName (required)
- assetType (enum from ASSET_TYPES)
- description, location, owner
- status (Active or Inactive)
- criticality (Low, Medium, High, Critical)
- userId (owner, required)
- isDeleted, deletedAt (soft delete)
- createdAt, updatedAt

Indexes:
- userId
- userId + createdAt desc

## Incident

Collection: incidents

Key fields:
- incidentId (unique generated business identifier)
- description (min 20 chars)
- assetId + embedded asset snapshot
- threatType, threatCategory, confidence
- likelihood, impact, riskScore, riskLevel
- aiModel, aiVersion, aiAnalyzedAt
- nistFunctions, nistControls, recommendations
- notes
- status (Open, InProgress, Resolved)
- userId
- guestAffected, sensitiveDataInvolved
- isDeleted, deletedAt
- createdAt, updatedAt, resolvedAt, resolvedBy

Indexes include:
- incidentId unique
- userId
- assetId
- createdAt desc
- riskLevel
- compound userId + status + createdAt desc

## RiskAssessment

Collection: riskassessments

Stores calculated risk snapshots and recommendations for ad-hoc or incident-based risk views.

Fields:
- incidentId (optional reference)
- likelihood, impact
- riskScore, riskLevel
- recommendation
- userId
- createdAt, updatedAt

## Threat

Collection: threats

Stores analyzed threat events.

Fields:
- threatType, threatCategory
- affectedAsset
- confidence
- likelihood, impact
- mitigationSteps
- nistFunctions, nistControls
- sourceDescription
- userId
- createdAt

## ThreatKnowledgeBase

Collection: threatknowledgebases

Canonical mapping of threat types to categories, NIST controls, and mitigations.

Fields:
- threatType (unique)
- threatCategory
- affectedAssetTypes
- nistFunctions
- nistControls
- mitigationSteps
- createdAt, updatedAt

## AuditLog

Collection: auditlogs

Captures key user actions.

Fields:
- actorUserId
- action
- entityType, entityId
- before, after
- meta
- ipAddress
- createdAt

## Constants

Defined in backend/utils/constants.js:

- ASSET_TYPES: POS, Server, WiFi, Database, Device, Other
- THREAT_TYPES: Phishing, Malware, Ransomware, DDoS, Unauthorized Access, Data Breach, Social Engineering, Network Attack
- INCIDENT_STATUS: Open, InProgress, Resolved
- NIST_FUNCTIONS: Identify, Protect, Detect, Respond, Recover
- RISK_LEVELS by score ranges:
  - Low: 1-4
  - Medium: 5-8
  - High: 9-12
  - Critical: 13-16

## Environment Variables

## Required for baseline backend operation

- MONGODB_URI
- JWT_SECRET

## Recommended for production readiness

- PORT (default 5000)
- NODE_ENV
- JWT_EXPIRATION (default 24h)
- JWT_REFRESH_SECRET (fallback to JWT_SECRET)
- JWT_REFRESH_EXPIRATION (default 7d)
- CORS_ORIGIN (comma-separated list)
- LOG_LEVEL (used by logger)

## Required for AI-backed analysis

- GEMINI_API_KEY
- GEMINI_MODEL (default gemini-1.5-flash)
- GEMINI_MODEL_VERSION (default v1beta)

## Seeded Default Data Behavior

On server startup, seed script does:

1. If no users exist, creates:
- admin@test.com / Admin123456
- staff@test.com / Staff123456

2. Upserts threat knowledge base entries from constants.

Important:
- This startup seeding runs automatically.
- For production, replace default credentials and review seed policy.
