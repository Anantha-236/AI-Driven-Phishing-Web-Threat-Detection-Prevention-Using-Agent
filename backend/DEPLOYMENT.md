# Render deployment

For a native Python web service using `backend/` as its Root Directory:

- Build Command: `pip install -r requirements.txt`
- Start Command: `PYTHONPATH=.. uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

The start command adds the repository root to Python's import path because the
application imports modules as `backend.*`. Use Render's environment variables
for the PostgreSQL connection (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and
`DB_PASSWORD`).

Render's current Python-version selection reads the repository-root
`.python-version` file (or the `PYTHON_VERSION` service environment variable).
`runtime.txt` is also included for compatibility with tools that recognize that
filename; it is not the Render version selector.
