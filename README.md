# Trototita

Pronounced tro-TÓ-ti-ta. Meaning: vulnerability.

A desktop vulnerability management app. It keeps findings in SQLite, imports CSV, JSON and Excel files and API pulls, prioritises findings with rules, tracks compliance and deadlines, and manages POA&Ms, RBDs and milestones. It runs on one computer, or against a team server for 5 to 10 people.

## Run

```bash
npm install
npm start          # run the desktop app
npm test           # unit and server tests
```

Requires Node 22.13 or newer. Electron 44 bundles a compatible runtime.

## Build installers

```bash
npm run pack      # unpacked app, for quick checks
npm run dist      # installers in dist/
```

- **macOS:** `dist/Trototita-<version>-arm64.dmg`, unsigned for now (right-click → Open on first launch).
- **Windows:** NSIS installer. Built by the GitHub Actions workflow on a Windows runner.
- **Linux:** AppImage. Built by the GitHub Actions workflow on an Ubuntu runner.

Code signing and an app icon are not set up yet (see TODO.md).

## What it does

| Area | Summary |
|---|---|
| Data grid | Any table. Filter per column (text, or `>5`, `<=7`), sort, select, edit cells, add rows, delete rows (per row or selected), export CSV, show/hide/reorder/rename columns, add or delete custom fields. SQL console runs on the rows the grid has loaded (read-only), or on the full database. |
| Charts | Pie, bar and line charts over any column. Click a slice to drill into the grid. Pin charts to the dashboard. |
| Dashboard | KPIs, pinned charts, alert counts, 90-day trend. |
| Alerts | Upcoming deadlines, overdue findings, non-compliant findings, overdue milestones. In-app list, dismiss for 7 days, desktop notifications. |
| Finding page | Details, status, deadline override, comments, history, linked POA&Ms. Open it from a finding's ID in the grid. |
| Rules | Priority bonuses and SLA days from conditions. Compliance policies (deadline, severity threshold, control mapping). |
| POA&M and RBD | Custom, DoD, FedRAMP and corrective-action templates. RBD adds decision fields. Milestones. CSV export. |
| Import | CSV, JSON and Excel files. Options: source name, remove duplicates, drop rows the file no longer has, Excel sheet, JSON path. API pulls with header and field mapping. |
| Cleaning | Preview then remove duplicates or findings not seen in N days. |
| Settings | Ten colour themes, font size, density, start view, alert settings, storage mode and team sign-in. |
| Threat intelligence | CISA Known Exploited Vulnerabilities and EPSS scores. Known-exploited findings get a priority bonus; EPSS adds a smaller one. Refreshed daily, or from the dashboard. |
| Asset inventory | Owner, criticality, environment and business unit per asset. Critical and High assets raise the priority of their findings. |
| Remediation metrics | Average days to fix by severity, share of findings overdue, and open findings by age. On the dashboard. |
| Risk reviews | Alerts when a risk acceptance (RBD) review is due or past its review date. |
| Scanner presets | One-click mappings for Nessus, Qualys and Tenable exports (Import → Scanner preset). |
| Saved views | Save the grid's filters and sort under a name, and reopen them from the grid. Shared with the team on the team server. |
| Attachments | Evidence files (up to 10 MB) on a finding or a POA&M / RBD record. |
| Excel export | POA&M and RBD records as an .xlsx workbook, with the template's column labels. |
| Backups | A verified copy of the database every day, the 14 most recent kept. Restore from Settings (desktop) or the command line (server). |
| Keyboard | Ctrl (or ⌘) with 1 to 9 switches between the first nine views. |

The template field sets are approximations of the common formats. Check them against your official template before submitting anything.

## Team server

One machine runs the server and owns the database. Each person runs the desktop app in **Team server** mode and signs in.

### 1. Create a certificate

```bash
server/make-cert.sh vulnmgt.internal 825     # or the server's IP address
```

This writes `server/cert.pem` (give it to each desktop user) and `server/key.pem` (keep it on the server). To use your organisation's certificate instead, pass its files to `--cert` and `--key`.

### 2. Create accounts

Passwords are read from standard input, or the `VULN_PASSWORD` environment variable. They must be at least 12 characters.

```bash
printf '%s' 'a long passphrase' | node server/server.js add-user dana editor
node server/server.js set-role dana admin
node server/server.js disable dana
node server/server.js list-users
node server/server.js audit 100
```

| Role | Can |
|---|---|
| viewer | Read everything |
| editor | Viewer rights, plus edit findings, comments, POA&Ms, milestones, imports and alert dismissals |
| admin | Editor rights, plus custom columns, rules, compliance policies, cleaning, and SQL |

### 3. Start the server

```bash
node server/server.js serve --cert server/cert.pem --key server/key.pem --port 8443 --db server/team.db
```

The server accepts HTTPS only. Sessions last 8 hours and are kept in memory, so a restart signs everyone out. Five failed sign-ins lock an account for 15 minutes. Every call and every denial is written to the audit log.

### Run the server in Docker

The `Dockerfile` builds the server only. It runs as a non-root user with a read-only filesystem, no Linux capabilities, and a health check.

```bash
docker build --target test -t vulnmgt-test .    # runs the full test suite inside Linux
mkdir -p deploy/certs && server/make-cert.sh vulnmgt.internal 825
mv server/cert.pem server/key.pem deploy/certs/
docker compose up -d --build
printf '%s' 'a long passphrase' | docker compose run --rm -T vulnmgt-server add-user dana editor --db /data/team.db
```

Accounts, the audit log, and the database live in the `vulnmgt-data` volume, so they survive restarts and image rebuilds. Mount your own certificate files into `./deploy/certs` (they must be named `cert.pem` and `key.pem`). Set `VULN_API_HOSTS` in the environment to approve API hosts.

### Team administration and backups

Admins can manage accounts and read the audit log from **Settings → Team accounts** in the desktop app. The same operations are on the command line:

```bash
node server/server.js backup                       # verified copy into backups/ beside the database
node server/server.js backups                      # list them
node server/server.js restore --from backups/<file>   # stop the server first; the current database is kept beside it
```

The server backs up once a day and refreshes the threat feeds once a day. The threat feeds (CISA and FIRST) need outbound HTTPS from the server.

### 4. Connect the desktop app

Open **Settings → Data storage and team sign-in**, choose **Team server**, enter the server address (for example `https://vulnmgt.internal:8443`), choose the certificate file, and sign in. Your personal settings stay on your computer. The data is on the server.

## Architecture

```
main.js              Electron main process: dialogs, notifications, settings, and the call() router
preload.js           contextBridge: the only API the page can use
renderer/            HTML, CSS and plain JavaScript UI (app.js, workflow.js)
src/db.js            SQLite schema, grid queries, upserts, dashboard aggregates
src/migrations.js    Workflow tables, added columns, history triggers (safe to run on every start)
src/handlers.js      Every data operation, with the minimum role for each one
src/rules.js         Priority, SLA due date, timeline bucket, compliance status
src/workflow.js      Comments, history, snapshots, compliance policies, alerts
src/poam.js          POA&M and RBD templates, records, milestones, CSV export
src/cleaning.js      Date normalisation, duplicate and stale-data removal
src/ingest.js        CSV, JSON, Excel and API importers
src/columns.js       Custom column model
src/users.js         Accounts, password hashing, roles, sessions, audit log
src/remote.js        Desktop client for the team server
server/server.js     Team server (HTTPS) and its command line
test/                Unit, workflow and server tests (npm test)
```

The same `src/handlers.js` code runs in the desktop app (local mode) and on the team server (team mode). In team mode, `call()` in `main.js` sends each operation to the server instead.

### Security

- **Renderer:** sandboxed, with `contextIsolation` on and no Node access. The page cannot navigate away, open windows, or get browser permissions. The CSP allows only the app's own scripts and styles, and blocks objects, base-tag changes, form submission and framing.
- **Imported text** is written with `textContent`, never `innerHTML`. JSON and Excel keys that could change an object's prototype are ignored.
- **Exports** neutralise spreadsheet formulas (CSV injection): text starting with `= + - @` is prefixed with an apostrophe.
- **SQL:** table and column names are validated before they reach SQL, and values are always bound as parameters. The SQL console is admin-only in team mode.
- **Team server:** HTTPS only. Passwords use scrypt, must be 12 to 256 characters, and five failed sign-ins lock an account for 15 minutes. Roles are checked on every call. Every call and denial is audit-logged. Connections have timeouts, and request bodies are size-limited.
- **API pulls on the server** are limited to hosts listed in `VULN_API_HOSTS`. Redirects are refused, so a pull cannot be sent somewhere that was not approved.
- **Sessions and tokens** live in memory only. Nothing sensitive is written to the settings file.
- **Dependencies:** `npm audit` reports 0 vulnerabilities. Some build-tool packages are pinned with npm `overrides` until electron-builder updates them.

To allow API pulls on the team server:

```bash
VULN_API_HOSTS=scanner.internal.example node server/server.js serve --cert server/cert.pem --key server/key.pem
```

## Known limits

- Single-machine team server, no high availability. Sessions are in memory, so a restart signs everyone out.
- Accounts are managed from the server command line. There is no admin screen yet.
- Login throttling is per account name, so it does not stop someone spreading guesses across many accounts. Put the server behind your network's controls.
- Control mapping checks a list of control IDs on each finding. It does not load a control catalogue.
- The grid loads up to 2,000 rows at a time.
