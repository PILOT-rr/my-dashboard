# Z Scanner Ultra V2.0 — Unified Application

## Run
1. Extract the ZIP.
2. Open `index.html` in a modern Chromium-based browser. A local static server is recommended for browser file picker/live file access consistency.
3. Sign in using the local demo credentials configured in `js/app.js`.
4. Load `FINAL_RESULTS.jsonl`, `domains.txt`, and `scanner.log` from the Overview/Logs workspace.

## V2.0 architecture
- One HTML document and one shared DOM. There is no iframe and no secondary dashboard document.
- `js/scanner-engine.js` owns JSONL parsing, normalization, deduplication, filters, pagination, record details, progress parsing, file health, live watch and exports.
- `js/app.js` owns navigation, local session UI, IndexedDB snapshots, settings and backup/restore.
- `css/app.css` styles the application shell; `css/engine.css` styles scanner views.
- Overview, Analytics, Domains and Logs are separate views over the same scanner state and loaded records.

## Data and safety
- Scanner input files are read-only; the app does not rewrite them.
- Source parsing errors and unknown evidence remain visible; no sample metrics are generated.
- Snapshots contain summary metrics only. Backups merge valid snapshots and preserve existing entries.
- XLSX library is not bundled. The export action falls back to CSV when SheetJS is unavailable.
- Login is a local UI gate only. The demo password is in client-side JavaScript; it is not secure authentication. IndexedDB is not encrypted.
- Browser file handles/live watch depend on browser support and user-granted permissions.

## Limits
This is a local browser application, not a server-backed multi-user service. No claim of bug-free or production-certified status is made. See `QA-REPORT.md`.
