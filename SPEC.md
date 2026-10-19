# Trototita: Specification and Status

Status key: **Done** = built and tested · **Partial** = works with stated limits · **Open** = not built, or needs a decision or outside access.

## 1. Platform
| Requirement | Status | Notes |
|---|---|---|
| Lightweight desktop app (Electron) | Done | Confirmed acceptable. Not in the browser. |
| SQLite storage | Done | Local file, or the team server's file |
| Windows, macOS, Linux installers | Partial | macOS DMG built and launched. Windows and Linux builds are set up in GitHub Actions (`.github/workflows/build.yml`) but have not been run yet. |
| Code signing | Open | Needs an Apple Developer ID and a Windows code-signing certificate (a cost decision). |
| App icon | Open | No icon file yet. The default Electron icon is used. |
| Dependency security | Done | `npm audit` reports 0 vulnerabilities. Electron 44.9.0 (latest stable). SheetJS xlsx 0.20.3 from the vendor CDN, which you approved. Build-chain packages pinned through npm `overrides` (see README). |
| Security review of the code | Done | Sandboxed renderer, navigation and pop-ups blocked, permission requests denied, CSV formula injection neutralised, prototype-key protection on imports, API import host allowlist on the server, redirect refusal, size limits, password length limits, login throttling, server timeouts. 74 tests. |

## 2. Data import
| Requirement | Status | Notes |
|---|---|---|
| CSV | Done | Header matching, unknown columns become custom fields |
| JSON files | Done | Array at the top level or at a dotted path |
| Excel (.xlsx, .xls) | Done | First sheet, or a named sheet |
| API pulls | Done | Static headers, dotted field mapping, one array per response. No pagination or token refresh yet. |
| Flexible column count | Done | Any number of columns; extra columns become custom fields |

## 3. Data cleaning
| Requirement | Status | Notes |
|---|---|---|
| Remove duplicates | Done | Duplicate = same CVE and asset from more than one source. Keeps the most recently seen row. Option on import, and a preview-then-remove tool. |
| Drop stale data | Done | Remove findings not seen in N days (preview first). Option on import to drop rows from a source that the file no longer contains. |
| Date normalisation | Done | ISO, US (1/5/2026), "05-Jan-2026", Excel serial dates |

## 4. Data management
| Requirement | Status | Notes |
|---|---|---|
| Column and row filtering | Done | Per-column text and numeric filters |
| Delete rows | Done | Selected rows, confirmed |
| Update rows | Done | Double-click a cell. Changes are recorded in history. |
| Customisable columns | Done | Show, hide, reorder, rename, add and delete custom fields. Built-in columns cannot be deleted. |
| Historical timelines | Done | Per-finding history (triggers, so SQL-console edits are recorded too). Daily snapshots drive the 90-day trend chart. |

## 5. Rules, compliance and deadlines
| Requirement | Status | Notes |
|---|---|---|
| Rule-based logic (e.g. severity = Medium) | Done | AND conditions; operators eq, neq, contains, gt, gte, lt, lte, in |
| Priority score | Done | CVSS, or a severity default, plus bonuses from matching rules |
| Deadline per severity or rule | Done | First matching rule that sets days wins |
| Per-CVE deadline | Done | Manual deadline on a finding overrides the computed one |
| Compliant / non-compliant | Done | Options: deadline met, severity threshold, control mapping, and combinations. Any failing policy makes a finding non-compliant. Closed findings are "Closed". |
| Timelines based on columns | Partial | Timeline lanes are fixed buckets (Overdue, 7 days, 30 days, Later). Lanes by custom column are not built. |

## 6. Tracking and workflow
| Requirement | Status | Notes |
|---|---|---|
| Comments per vulnerability | Done | Author from Settings, delete, shown on the finding page |
| POA&M and RBD | Done | Both kinds, with Custom, DoD, FedRAMP and corrective-action templates. RBD adds decision fields. Linked to findings. Export to CSV. |
| Template accuracy | Open | DoD and FedRAMP field sets are approximations. Check against the official templates before use. |
| Milestone tracking | Done | Per POA&M or RBD, with done dates and overdue detection |
| Follow-up alerts | Done | Upcoming deadlines, overdue, non-compliant, overdue milestones. In-app list with dismiss, dashboard counts, and desktop notifications (checked at start and every 30 minutes). |

## 7. Charts and dashboards
| Requirement | Status | Notes |
|---|---|---|
| Pie, bar and line charts | Done | Built as SVG, no chart library |
| Choose the column for buckets | Done | Any column, including custom fields |
| Drill-down | Done | Click a slice, bar or point to open the grid filtered to it |
| Charts adapt to any column set | Done | Works on any column of the table |
| Dashboard | Done | KPIs, pinned charts, alert counts, trend |

## 8. Team use
| Requirement | Status | Notes |
|---|---|---|
| Central server for 5 to 10 people | Done | One machine owns the database. Desktop apps connect over HTTPS. |
| HTTPS | Done | HTTP is refused. Self-signed certificate via `server/make-cert.sh`, or your organisation's certificate. |
| App accounts | Done | scrypt password hashes, minimum 12 characters, managed from the server command line |
| Roles | Done | viewer (read), editor (edit findings, POA&Ms, imports), admin (schema, rules, policies, cleaning, SQL) |
| Audit log | Done | Every call and every denial is recorded. Viewed with `node server/server.js audit`. |
| Login throttling | Done | Locks an account for 15 minutes after 5 failed attempts |
| Admin screens in the app | Open | Accounts are managed from the server command line only |
| Team mode tested in the app | Partial | Server and client code are tested (including a live server run). The Electron team mode has not been run end to end. |
| Active Directory or SSO | Out of scope | Decided against for now |

## 8a. Recommended features (added and built)
| Feature | Status | Notes |
|---|---|---|
| Backups with restore | Done | Daily, verified (integrity check), 14 kept. Desktop restore in Settings; server restore on the command line. Restore keeps a copy of the replaced database. |
| Known-exploited (KEV) and EPSS enrichment | Done | Refreshed daily from CISA and FIRST, or on demand. Priority bonus: KEV +3, EPSS × 5. Feeds are fixed trusted URLs. |
| Risk-acceptance review reminders | Done | Alerts when an RBD review is due within the lead time, or past its review date. |
| Remediation metrics | Done | Average days to fix by severity (from the history log), percentage overdue, open findings by age. |
| Scanner import presets | Done | Nessus, Qualys and Tenable column mappings. Qualys numeric severity and Active/Fixed status words handled. |
| Asset inventory with criticality | Done | Owner, criticality, environment, business unit. Criticality raises priority. |
| Saved grid views | Done | Filters and sort per table; shared on the team server. |
| Attachments | Done | Up to 10 MB per file, on a finding or a POA&M/RBD record. Names stripped of path parts. |
| Excel export of POA&M / RBD | Done | Workbook with the template's column labels. |
| Admin screens for accounts and audit log | Done | Desktop Settings, for team admins. The last enabled admin cannot be disabled or demoted. |
| Keyboard shortcuts | Partly | Ctrl/⌘ + 1 to 9 for views. No command palette or full keyboard navigation yet. |
| Scheduled API pulls | Open | Needs a decision on storing API tokens (not stored today). |
| Weekly summary by email | Open | Needs email, which the spec excludes. Your call. |
| Two-factor sign-in | Open | Not started. |
| Encryption of the database at rest | Open | Needs an encrypted SQLite build or an encrypted volume. |
| PDF summary export | Open | Needs a PDF library. |
| Automatic desktop updates | Open | Depends on code signing. |

## 9. Decisions log
| # | Decision |
|---|---|
| 1 | Electron desktop app is acceptable as "lightweight". |
| 2 | RBD = risk-based decision. POA&M and RBD support selectable templates (Custom, DoD, FedRAMP, other). |
| 3 | Compliance: all options available. Deadline is the primary focus. |
| 4 | Alerts: in-app and desktop. Upcoming deadline, overdue, non-compliant, overdue milestones. |
| 5 | Team use: central HTTPS server with per-user login (option B), 5 to 10 users. |
| 6 | Login: app accounts only. No Active Directory or SSO for now. |
| 7 | Interface stays a desktop app. The team server is API-only. |
| 8 | Charts: the richer version lives on the Charts view, with drill-down and customisation. The dashboard shows pinned charts. |

## 10. Open items needing a decision or outside access
1. **Code signing.** Needs an Apple Developer ID and a Windows certificate, which cost money. Who will own them?
2. **Icon.** Send an icon file (1024 px PNG) and I'll add it.
3. **Windows and Linux.** Push the repository to GitHub so the workflow runs, or tell me which machines to test on.
4. **Template check.** Confirm the DoD and FedRAMP field sets against your official templates.
5. **Team certificate.** Use the self-signed script, or your organisation's certificate? Who distributes the certificate file to each desktop?
