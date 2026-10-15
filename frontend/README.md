# React analyst dashboard

The user-facing interface for threat-hunting campaigns, detection review, findings and reporting. Source code is provided; the generated Vite bundle is intentionally excluded from Git history.

## Source and tooling

- [`src/main.jsx`](src/main.jsx) — React application views and client-side workflow.
- [`src/index.css`](src/index.css) — application styling.
- [`src/reports.js`](src/reports.js) — client-side reporting helpers.
- [`package.json`](package.json), [`package-lock.json`](package-lock.json) — dependency and build declarations.
- [`vite.config.js`](vite.config.js) — development/build configuration.

## Run locally

With Node.js/npm installed:

```bash
npm ci
npm run dev
```

Build with `npm run build`. On systems without npm, the tracked [GitHub Actions frontend build](../.github/workflows/frontend-build.yml) is the independent compilation check **once it runs successfully**; its existence alone is not proof of a passed build.

Backend API availability, authentication and SIEM/model connections are separate runtime prerequisites. Consult [developer setup](../docs/DEVELOPER_SETUP.md) and [security notes](../docs/SECURITY_AND_PRIVACY.md).
