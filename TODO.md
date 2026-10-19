# TODO

Status of the spec is in SPEC.md. This list is what is left.

## Built this session (see SPEC.md 8a)
Backups and restore, KEV and EPSS, RBD review reminders, remediation metrics, scanner presets, asset criticality, saved views, attachments, Excel export, team admin screens, keyboard shortcuts (partly). 96 tests, passing on the host and in Docker.

## Still to build (in rough priority order)
- [ ] Scheduled API pulls. Decide how API tokens are stored first (they are not stored today).
- [ ] Two-factor sign-in (TOTP) for team accounts.
- [ ] Encryption of the database at rest (encrypted SQLite build or encrypted volume).
- [ ] PDF summary export (needs a PDF library).
- [ ] Command palette and full keyboard navigation.
- [ ] Weekly summary email (needs your decision on email).
- [ ] Automatic desktop updates (needs code signing first).
- [ ] Admin password reset in the desktop app (available on the command line only).

## Needs a decision from you
- [ ] Code signing: Apple Developer ID and Windows code-signing certificate.
- [ ] App icon (1024 px PNG).
- [ ] Confirm DoD and FedRAMP POA&M field sets against the official templates.
- [ ] Team certificate: self-signed (`server/make-cert.sh`) or your organisation's CA.

## Needs a machine or account outside this Mac
- [ ] Push to GitHub and check the Windows and Linux jobs in `.github/workflows/build.yml`.
- [ ] Run `npm test` and `npm start` on Windows and Linux.
- [ ] Run one full team session in the Electron app (desktop in team mode against a running server).

## Docker (tested)
- [x] Test suite passes inside a Linux container (`docker build --target test .`, 74 tests).
- [x] Team server runs under docker compose: healthy, non-root, read-only filesystem, data survives restart.
- [ ] Publish the server image to a registry for the team (needs a registry you control).
- [ ] Add a Docker-based smoke test to CI.

## Dependency upkeep
- [ ] Remove the `overrides` block in package.json (roarr, global-agent, @electron/get, sprintf-js path) once electron-builder releases versions that do not need it. Re-run `npm audit` after every update.
- [ ] Re-run `npm audit` and the SheetJS CDN check before each release. Update SheetJS only from cdn.sheetjs.com.

## Smaller follow-ups
- [ ] Admin screens for team accounts (currently the server command line only).
- [ ] Timeline lanes by a custom column (SPEC section 5).
- [ ] API pagination and token refresh for the API importer.
- [ ] Virtual scrolling for very large grids (the grid loads up to 2,000 rows).
