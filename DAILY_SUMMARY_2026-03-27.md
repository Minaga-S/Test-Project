# Daily Summary - 2026-03-27

## Overview
Today's work focused on local testing support, frontend usability improvements, and dashboard/settings UX refinements.

## Backend Updates
- Expanded CORS defaults to include localhost origins for local frontend testing.
- Updated CORS origin logic to merge default origins with configured `CORS_ORIGIN` values.

## Frontend Updates
- Added automatic local/production API base URL selection in the API client.
- Improved logout handling reliability by standardizing button behavior.
- Added safer user-info rendering guards to avoid null element errors.
- Added collapsible sections for dashboard and risk analysis views.
- Added summary badges for incident and vulnerability context in dashboard collapsible headers.
- Reworked dashboard quick actions layout and placement for cleaner flow.
- Improved responsive behavior for collapsible sections and quick actions.
- Added sidebar toggle behavior (desktop collapse + mobile drawer behavior).
- Added hover-expand behavior support for collapsed sidebar states.

## Settings and Help Improvements
- Simplified settings to user-facing tabs only (Profile, Password, Notifications).
- Removed backend/developer-only settings from the UI.
- Added dedicated help links in Settings:
  - User Guide
  - FAQ
  - Contact Support
- Added standalone guide pages:
  - `frontend/user-guide.html`
  - `frontend/faq.html`
  - `frontend/contact-support.html`
- Added persistent stylesheet-based tab/help styling to match the site theme.

## Documentation Updates
- Added localhost testing instructions in README, including backend and frontend run flow.

## Files Added
- `DAILY_SUMMARY_2026-03-27.md`
- `frontend/user-guide.html`
- `frontend/faq.html`
- `frontend/contact-support.html`

## Validation Notes
- Editor diagnostics were used during implementation cycles and major modified files were checked for errors.
- Frontend routes were prepared for local checks at `http://localhost:3000`.

## Next Suggested Follow-Up
- Do a final visual QA pass on desktop and mobile breakpoints for sidebar interactions.
- Confirm tab states and help links in Settings after hard refresh to avoid stale cache effects.
