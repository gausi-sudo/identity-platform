# Working notes

Self-hosted identity & access management, based on [Casdoor](https://github.com/casdoor/casdoor) (Apache-2.0). Go backend + React frontend.

## Run locally

```
./start.sh     # builds + runs the backend API on http://127.0.0.1:8000
./stop.sh      # stops it
```

- Uses an embedded SQLite database that is **reset to a clean state on every start**, so local runs are deterministic. No external database required.
- The React frontend in `web/` is not needed for backend/API work.

## Seed sample data

```
./seed-local-data.sh
```

After the server is up, creates sample organizations and users and writes
the local `niro/credentials.yaml`. The built-in admin is `admin` / `123`.

## Security testing

Security testing runs via Niro on pull requests. To exercise it against a
local instance:

1. `./start.sh` — the target `http://127.0.0.1:8000` is already authorized in `niro/scope.yaml`.
2. `./seed-local-data.sh` — provides the accounts Niro authenticates with.
3. Open a PR — Niro runs against the live instance and reports results on the PR.

## Layout

- Go backend — `controllers/`, `object/`, `routers/`, `main.go`
- React frontend — `web/`
- `niro/` — security-testing config (authorized scope, resource caps, credential format reference)
