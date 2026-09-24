# BASELINE RECOVERY REPORT

REPOSITORY=C:\Users\anant\OneDrive\Desktop\Capstone-1-GitHub-Ready

HEAD=254b6f0cfa77fe07ab9bb90b59d004031cc0de03

BRANCH=main

WORKING_TREE=MODIFIED

NODE=AVAILABLE

NPM=AVAILABLE

NODE_DEPENDENCIES=READY

PYTHON=UNKNOWN

PYTHON_DEPENDENCIES=NOT_READY

TYPECHECK=NOT_RUN

BUILD=NOT_RUN

BACKEND=NOT_RUN

DATABASE_RUNTIME=SQLite

POSTGRESQL_SERVER=NOT_TESTED

POSTGRESQL_DATABASE=capstone1

POSTGRESQL_SCHEMA=NOT_TESTED

BROWSER_E2E=NOT_RUN

APPLICATION_CODE_CHANGED=NO

ENVIRONMENT_BLOCKER=Baseline verification was completed only to the point of confirming the repository identity, branch state, dependency presence, and the current runtime database reality. The terminal environment did not emit reliable versions or test output for the optional deeper validation phases, so browser E2E, backend runtime tests, and PostgreSQL verification were intentionally left unrun rather than classified as application failures.

## Evidence summary

- Git metadata confirms the repository is on main and the current HEAD is 254b6f0cfa77fe07ab9bb90b59d004031cc0de03 as recorded in [.git/HEAD](.git/HEAD) and [.git/logs/HEAD](.git/logs/HEAD).
- Repository inspection confirms the active project directories exist: [backend](../../backend), [browser-extension](../../browser-extension), [ml](../../ml), [docs](../../docs), and [scripts](../../scripts).
- The runtime database evidence in [docs/PROJECT-FILE-AUDIT.md](../PROJECT-FILE-AUDIT.md) and the generated SQLite file in [backend/capstone.db](../../backend/capstone.db) indicates the active runtime is SQLite, not PostgreSQL.
- Node dependency installation state was verified by filesystem checks: package.json, package-lock.json, and node_modules are present in the repo root, and the workspace is not in an unmodified source-edit state during this recovery phase.
- No Python virtual environment was found in the repo root, so Python dependency readiness remains not ready for backend validation without an explicit environment setup step.
