
# Phishing Simulation (Local)

> **For authorized internal security awareness training only.**
> Do **NOT** store or request employees' real passwords. This tool only records a *credential attempt* and a hash of whatever is entered, never the raw password.

## Quick Start

1. Install Node.js 18+
2. In this folder:
   ```bash
   npm install
   npm start
   ```
3. Open http://localhost:3000

## First-run Setup + Admin Login

Dashboard, campaigns, exports, and analytics APIs are **admin-only**.

On first run (when there is no admin user), open:
- `/setup`

Create your admin username + password, then log in at:
- `/admin/login`

### Recommended environment variables

Set this before starting in production-like demos:

```bash
set SESSION_SECRET=...some-long-random-string...
```

## Features
- Create campaigns and add target users.
- Generates unique tracking links per target.
- Tracks **link opens**, **name submissions**, and **credential attempts** (stores only username and a **non-recoverable hash** + length).
- Beautiful landing page themed as “Your Organisation Free Amazon Voucher” (editable).
- Admin dashboard with metrics and CSV export.
- Fully local SQLite database (`data/phish.db`).

## Default Pages
- Admin Dashboard: `/`
- Campaigns List: `/campaigns`
 - Admin Login: `/admin/login`
 - Admin Settings: `/admin/settings`
- Campaign Detail (add targets, copy links): `/campaigns/:id`
- Landing page (tracked): `/l/:token`
- Fake login page (tracked): `/login?token=...`

## CSV Export
- All events: `/export/all.csv`
- Clicks: `/export/clicks.csv`
- Name submissions: `/export/names.csv`
- Credential attempts: `/export/creds.csv`

## Ethical Use
- Displayed warnings explain this is a simulation.
- Password field is a **decoy**; we store only a salted SHA-256 hash and length to prove attempt without risking exposure.
- You can edit views in `views/` to match your organisation branding.


---

Admin Notice: End-user pages are realistic with no training disclaimer. Use only with proper internal approvals.

## Production HTTPS link

Set an HTTPS domain for the "Production link" shown on campaign pages:

```bash
# example
set PROD_DOMAIN=sim.company.com
# or on linux/mac
export PROD_DOMAIN=sim.company.com
```

If not set, the app will still show an HTTP test link for localhost/internal testing.
