# Render deployment

Use the repository's `render.yaml` as a Render Blueprint. It configures a native
Python web service from the repository root, installs the backend dependencies,
starts the FastAPI application as the `backend` package, and checks
`/api/v1/health`.

The start command must import `backend.main:app`, not `main:app`. Keeping the
repository root as Render's working directory preserves the application's
absolute `backend.*` imports and the same import behavior used by local tests.

Set the prompted PostgreSQL connection values (`DB_HOST`, `DB_PORT`, `DB_NAME`,
`DB_USER`, and `DB_PASSWORD`) when creating the Blueprint. Keep credentials in
Render's environment settings, not in the repository.

Render's current Python-version selection reads the repository-root
`.python-version` file (or the `PYTHON_VERSION` service environment variable).
`runtime.txt` is also included for compatibility with tools that recognize that
filename; it is not the Render version selector.

The backend uses PostgreSQL through the `DB_*` settings above; it does not use a
local SQLite database file for runtime persistence.
