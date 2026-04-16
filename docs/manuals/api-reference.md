# API Reference

## Conventions

- Base URL (local): http://localhost:5000/api
- Authentication: Bearer JWT for all routes except /auth/register, /auth/login, /auth/refresh
- Content-Type: application/json
- Common success shape: { success: true, ...payload }
- Common error shape: { success: false, message, errors? }

## Health

### GET /health

Returns service heartbeat.

## Authentication Endpoints

### POST /auth/register

Request:

```json
{
  "email": "staff@example.com",
  "password": "StrongPass123",
  "fullName": "Staff User"
}
```

Validation:
- email must be valid
- password min length 8
- fullName required

Response:
- 201 with token, refreshToken, user

### POST /auth/login

Request:

```json
{
  "email": "staff@example.com",
  "password": "StrongPass123"
}
```

Response:
- 200 with token, refreshToken, user
- 401 invalid credentials
- 403 inactive user

### POST /auth/refresh

Request:

```json
{
  "refreshToken": "<refresh-token>"
}
```

Response:
- 200 with new token and refreshToken
- 401 invalid/expired refresh token

### GET /auth/profile

Auth required.

Response:
- user profile object

### PUT /auth/profile

Auth required.

Request (all optional):

```json
{
  "fullName": "Updated Name",
  "department": "IT"
}
```

### POST /auth/change-password

Auth required.

Request:

```json
{
  "currentPassword": "OldPass123",
  "newPassword": "NewPass123"
}
```

## Asset Endpoints

All asset endpoints require auth.

### POST /assets

Request:

```json
{
  "assetName": "Core PMS Server",
  "assetType": "Server",
  "description": "Property management backend",
  "location": "Server Room",
  "status": "Active",
  "criticality": "Critical",
  "owner": "IT Team"
}
```

Validation:
- assetName required
- assetType required

### GET /assets

Returns assets for current user.

### GET /assets/asset-types

Returns allowed asset types.

### GET /assets/search?query=term

Regex search on assetName, description, location.

### GET /assets/:id
### PUT /assets/:id
### DELETE /assets/:id

- id must be valid Mongo ObjectId
- delete is soft delete

## Incident Endpoints

All incident endpoints require auth.

### POST /incidents

Request:

```json
{
  "assetId": "<mongo-id>",
  "description": "Detailed incident narrative with at least twenty characters.",
  "incidentTime": "2026-04-02T12:20",
  "guestAffected": false,
  "sensitiveDataInvolved": true
}
```

Validation:
- assetId must be ObjectId
- description length >= 20

Behavior:
- classifies threat via AI service
- calculates risk score and level
- maps NIST controls
- stores recommendations

### GET /incidents
### GET /incidents/search?query=term
### GET /incidents/:id
### PUT /incidents/:id
### DELETE /incidents/:id

Delete is soft delete.

### PUT /incidents/:id/status

Request:

```json
{ "status": "Resolved" }
```

Allowed status values:
- Open
- InProgress
- Resolved

### POST /incidents/:id/notes

Request:

```json
{ "note": "Followed incident response playbook step 2." }
```

## Threat Endpoints

All threat endpoints require auth.

### POST /threats/analyze
### POST /threats/classify

Request:

```json
{ "description": "Suspicious email prompted credentials submission by staff." }
```

Description min length is 20.

### GET /threats/knowledge-base
### GET /threats/categories
### GET /threats/types
### GET /threats/details/:threatType

## Risk Endpoints

All risk endpoints require auth.

### POST /risk/calculate

Request:

```json
{ "likelihood": 3, "impact": 4 }
```

Constraint:
- both values must be integers in [1, 4]

### GET /risk/assessment/:incidentId
### GET /risk/matrix
### GET /risk/trends
### GET /risk/by-asset
### GET /risk/summary

## NIST Endpoints

All NIST endpoints require auth.

### GET /nist/functions
### GET /nist/controls/:threatType
### GET /nist/mapping/:incidentId
### GET /nist/recommendations/:threatType

## Dashboard Endpoints

All dashboard endpoints require auth.

### GET /dashboard/metrics
### GET /dashboard/metrics/trends
### GET /dashboard/charts/risk-distribution
### GET /dashboard/charts/threat-categories
### GET /dashboard/charts/vulnerable-assets
### GET /dashboard/recent-incidents
### GET /dashboard/overview

## HTTP Status Guidance

Common statuses used by controllers:

- 200 successful read/update
- 201 resource created
- 400 validation failures / malformed input
- 401 missing or invalid authentication
- 403 inactive account (auth login path)
- 404 resource not found
- 429 rate limit exceeded
- 500 unexpected server errors
