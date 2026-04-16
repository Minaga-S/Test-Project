# Calculation and Visualization Reference

## Purpose

This page explains how the application turns incident reports, assets, scan history, and CVE data into the risk numbers, threat labels, recommendations, and charts used across the UI.

It is the reference for:
- Threat classification.
- Risk scoring and risk levels.
- NIST function/control mapping.
- CVE enrichment and security context building.
- Dashboard metrics and chart data.
- Risk analysis charts and tabular summaries.

## Data Flow Overview

The core flow is:
1. A user submits an incident or loads a dashboard/risk page.
2. The backend loads the relevant asset, incident, and scan history.
3. CVE data is attached to the security context when available.
4. The threat classifier blends AI output with threat intelligence.
5. Risk scoring converts likelihood and impact into a numeric score and label.
6. The frontend consumes that data to render charts, tables, and priority lists.

## Threat Classification

Threat classification is handled in the backend by the threat classification service.

### Inputs used

The classifier can use:
- The incident description.
- CVEs found in the asset security context.
- Live scan details such as discovered services.
- NIST threat intelligence mappings.
- AI model output from the Gemini-backed analysis path.

### Classification flow

The service first extracts CVEs from the security context. It then calls the AI analysis layer and also asks the NIST threat intelligence service to classify the threat from CVEs and the description.

The final classification is blended from those sources:
- The threat type is usually the AI result unless threat intelligence provides a stronger result.
- The threat category comes from the AI result or the threat intelligence result.
- Likelihood and impact are either derived deterministically from CVE severity or clamped from AI fallbacks.
- NIST functions and controls come from the threat-to-NIST mapping.

### Ransomware guardrail

There is an explicit ransomware guardrail:
- If the description contains ransomware keywords or the threat is already classified as ransomware, the classification is forced to ransomware.
- If the description also contains multiple severe operational indicators, likelihood and impact are raised to the critical range.

This prevents low-confidence model output from downgrading obviously severe ransomware reports.

## Threat Types And Threat Levels

Threat types come from the NIST threat intelligence service.

The supported threat types are:
- Malware
- Ransomware
- Data Breach
- DDoS
- Unauthorized Access
- Phishing

### How threat types are matched from CVEs

Each CVE is scored against threat patterns. The code uses:
- Pattern matches in the CVE description.
- Keyword matches in the CVE description.
- CVE severity.
- CVSS base score.

For each threat type and each CVE:
- Pattern match adds 30 points.
- Each keyword match adds 15 points.
- Severity match adds 20 points.
- CVSS >= 9.0 adds 25 points.
- CVSS >= 7.0 adds 15 points.
- CVSS >= 5.0 adds 5 points.

The threat types are then sorted by total score.

### Confidence calculation for CVE-based threat matching

The confidence returned for CVE-based analysis is:
- `min(95, 50 + (score / 100) * 45)`

That means a strong CVE signal can push confidence close to, but never above, 95.

### Description-only classification

If there are no CVEs, the system falls back to description matching.

That path also uses keyword/pattern scoring, but it is simpler:
- Pattern matches add 30 points.
- Keyword matches add 20 points.
- The highest-scoring threat type wins.

If nothing matches, the fallback threat type is `Unknown`.

## Risk Scoring

Risk scoring is deterministic once likelihood and impact are known.

### Formula

The base formula is:

$$
risk\ score = likelihood \times impact
$$

Both inputs must be integers from 1 to 4.

### Risk levels

The score is converted into a risk level using these bands:
- 1-4 = Low
- 5-8 = Medium
- 9-12 = High
- 13-16 = Critical

### Why those bands matter

The score bands are intentionally strict so that the highest combination of likelihood and impact is the only path to `Critical`.

### Risk recommendations

Each risk level also has a human-readable recommendation:
- Low: monitor with standard security practices.
- Medium: plan mitigation and monitor closely.
- High: address as soon as possible.
- Critical: immediate action required, possibly including isolation of affected systems.

## NIST Mapping

After the threat type is selected, the application maps it to NIST CSF functions and controls.

### Example mappings

- Malware -> Protect, Detect, Respond
- Ransomware -> Protect, Detect, Respond, Recover
- Data Breach -> Protect, Detect, Respond
- DDoS -> Detect, Respond
- Unauthorized Access -> Identify, Protect, Detect
- Phishing -> Protect, Detect

The matching controls are similarly threat-specific. These control codes are used in recommendations and compliance views.

## CVE Enrichment

CVE enrichment starts from the asset security context.

### Building the query

The security context builder creates a query from:
- CPE URI.
- Vendor.
- Product.
- Product version.
- OS name, if the value looks like a real operating system.

### Data sources

The security context also tracks where the data came from:
- Live scan source.
- CVE source.
- Enrichment state.

### Scan history and fallback behavior

The application prefers persisted scan history when it exists.

If there is no completed scan history, it builds a fallback context from the asset profile and the latest enrichment data. That fallback still includes:
- Asset metadata.
- Live scan request target and requested ports.
- A CVE query object.
- Empty or partial CVE matches, depending on what has been found.

### CVE match fields shown in the UI

CVE entries may surface:
- CVE ID.
- Severity.
- CVSS score.
- Published date.
- Description.
- Confidence and source metadata.

## Dashboard Metrics

The dashboard shows four top-level metrics:
- Total assets.
- Open incidents.
- Critical risks.
- Resolved issues.

### How each metric is calculated

All metric values are counts scoped to the current user.

- Total assets: count of assets owned by the user.
- Open incidents: count of incidents with status `Open`.
- Critical risks: count of incidents with risk level `Critical` and status not equal to `Resolved`.
- Resolved issues: count of incidents with status `Resolved`.

### Dashboard deltas

The dashboard also calculates week-over-week deltas.

For each metric, the code compares the current value to the count at least 7 days ago and subtracts the older count from the current count.

### Dashboard sparklines

The dashboard sparkline widgets use 7-day trend arrays returned by the backend.

Each series is cumulative by day:
- Total assets.
- Open incidents.
- Critical risks.
- Resolved issues.

The chart labels are ISO date strings for each of the last 7 days.

## Dashboard Graphs

### Risk distribution chart

This is a doughnut chart built from incident risk levels.

Data source:
- Count incidents grouped by `Critical`, `High`, `Medium`, and `Low`.

What it shows:
- The share of incidents in each risk band.

### Threat categories chart

This is a doughnut chart built from incident threat types.

Data source:
- Count incidents grouped by `threatType`.

What it shows:
- The distribution of threat categories currently affecting the user’s assets.

### Vulnerable assets chart

This is a bar chart built from incident counts per asset.

Data source:
- Count incidents grouped by asset name.
- Sort descending by count.
- Keep the top 10 assets only.

What it shows:
- Which assets have the most incident activity and are therefore the most exposed or repeatedly affected.

## Risk Analysis Graphs

The risk analysis page builds a more operational view of the same data.

### Risk matrix

This is a bubble chart.

Data source:
- Each incident becomes one bubble.
- x = likelihood.
- y = impact.
- r = bubble radius, fixed at 15.
- label = incident ID.
- color = incident risk level.

What it shows:
- Where incidents sit on the likelihood/impact matrix.
- Clusters of high likelihood and high impact issues become visually obvious.

### Risk distribution

This is a doughnut chart on the risk analysis page as well.

It uses the same risk-level counts as the dashboard.

### Risk trends

This is a line chart.

Data source:
- Incidents sorted by creation date ascending.
- The y-axis uses each incident’s `riskScore`.
- The x-axis uses the incident creation date as a localized string.

What it shows:
- The sequence of risk scores over time.
- Whether incidents are getting more severe or less severe over time.

### Risk breakdown table

This is a table rather than a graph, but it is part of the same visualization set.

For each incident, it shows:
- Incident ID.
- Asset.
- Threat type.
- Likelihood.
- Impact.
- Risk score.
- Risk level.
- Priority.

Priority is derived from risk level:
- Critical -> Urgent
- High -> High
- Medium -> Medium
- Low -> Low

### Recommendation priority list

This is a ranked list, not a chart.

It sorts incidents by risk level so the most urgent items appear first.

## Incident Detail Enrichment

When an incident is opened, the UI displays enrichment details from the security context.

Shown values include:
- Scanned IP.
- Open ports.
- Operating system.
- CPE URI.
- Vendor.
- Product name.
- Product version.
- Attached CVE matches.
- NIST functions and controls.
- Recommendations.

These values are sourced from persisted scan history when available, otherwise from the merged asset/security context payload.

## Source References

- [Risk calculation service](../../backend/services/riskCalculationService.js)
- [Threat classification service](../../backend/services/threatClassificationService.js)
- [NIST threat intelligence service](../../backend/services/nistThreatIntelService.js)
- [Asset security context service](../../backend/services/assetSecurityContextService.js)
- [CVE enrichment service](../../backend/services/cveEnrichmentService.js)
- [Dashboard controller](../../backend/controllers/dashboardController.js)
- [Risk controller](../../backend/controllers/riskController.js)
- [Incident controller](../../backend/controllers/incidentController.js)
- [Frontend chart helpers](../../frontend/js/utils.js)
- [Dashboard page logic](../../frontend/js/dashboard.js)
- [Risk analysis page logic](../../frontend/js/risk-analysis.js)
- [Incident logs page logic](../../frontend/js/incident-logs.js)
