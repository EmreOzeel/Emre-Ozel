# Python → Go Backend Migration Plan

Both backends share the same PostgreSQL database. Traffic is routed
by nginx based on the `MIGRATION_PHASE` environment variable.

## Architecture during migration

```
                     ┌─────────────┐
       HTTPS ──────▸ │    nginx    │
                     │ (routing)   │
                     └──┬──────┬───┘
                        │      │
          MIGRATION_PHASE      │
          0: all Python        │
          1: split             │
          2: all Go            │
                        │      │
                   ┌────▼──┐ ┌─▼───────┐
                   │Python │ │   Go    │
                   │:8000  │ │  :8000  │
                   └───┬───┘ └───┬─────┘
                       │         │
                   ┌───▼─────────▼───┐
                   │   PostgreSQL    │
                   └─────────────────┘
```

---

## Phase 0 — Parallel running (current)

Both backends run side-by-side against the same database.

- [x] Go backend built and running on internal port 8000
- [x] Python backend running on internal port 8000
- [x] nginx routes all traffic to Python (`MIGRATION_PHASE=0`)
- [x] `scripts/compare_backends.sh` created (supports `--body` flag)
- [x] Response shape mismatches identified and fixed:
  - [x] `/api/health` — added `version` field
  - [x] `/api/live-events` — added `offset`/`limit` to response, max limit=5000
  - [x] `/api/live-flows` — added `offset`/`limit` to response, added missing filters
  - [x] `/api/notifications/unread-count` — `count` → `unread`
  - [x] `/api/notifications` — `unread_only` default false (not true)
  - [x] `/api/threat-indicators` — response uses `{"total", "items"}` wrapper
  - [x] `/api/live-incidents` — added `behavior_type` filter
  - [x] `/api/analyses` — added `workflow_state`/`assigned_to_me` filters
  - [x] `/api/users` — includes `team_id` field
- [x] Response shape tests added (`response_shape_test.go`):
  - [x] 10 endpoint shape verifications (all expected JSON keys)
  - [x] 14 auth enforcement tests (401 without token)
  - [x] Pagination tests (limit/offset)
  - [x] Direct-array endpoints verified (analyses, notifications, etc.)

### How to test

```bash
# Start both backends
docker compose -f docker-compose.prod.yml up -d

# Get a token from Python backend
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .token)

# Compare (Go is exposed on 8001 via docker-compose.go.yml for direct access)
./scripts/compare_backends.sh "$TOKEN"
```

---

## Phase 1 — Route-by-route migration

Set `MIGRATION_PHASE=1` in `.env` and restart nginx.

Migrated routes go to Go, everything else stays on Python.

### Route groups to verify and enable

| Route group | Go handler file | Status |
|---|---|---|
| Auth (`/api/auth/*`) | `auth.go` | Ready |
| Health (`/api/health`) | `handler.go` | Ready |
| Analyses (`/api/analyses/*`) | `analysis.go` | Ready |
| Live Events (`/api/live-events/*`) | `live_events.go` | Ready |
| Live Flows (`/api/live-flows/*`) | `live_flows.go` | Ready |
| Live Incidents (`/api/live-incidents/*`) | `incidents.go` | Ready |
| Notifications (`/api/notifications/*`) | `notifications.go` | Ready |
| Suppressions (`/api/suppressions/*`) | `suppressions.go` | Ready |
| Work Queue (`/api/work-queue`) | `workflow.go` | Ready |
| Dashboard (`/api/dashboard/summary`) | `dashboard.go` | Ready |
| Workflow (`/api/analyses/:id/workflow`) | `workflow.go` | Ready |
| Users (`/api/users`) | `workflow.go` | Ready |
| Correlation Rules | `correlation.go` | Ready |
| Threat Intel | `threat_intel.go` | Partial (feed fetch = 501) |
| Baselines | `baseline.go` | Read-only |
| GeoIP | `geoip.go` | Cache-only |
| Path Analysis CRUD | `path_analysis.go` | CRUD ready, engine = 501 |
| Monitoring CRUD | `monitoring.go` | CRUD ready, run = 501 |
| Attack Sessions | `attack_sessions.go` | Ready |

### Verification checklist per route group

For each group, before enabling in nginx:

1. Run `compare_backends.sh` for that endpoint group
2. Compare JSON response shapes (not just status codes)
3. Test create/update/delete operations
4. Check pagination and filtering match
5. Enable in nginx config

---

## Phase 2 — Collector migration

Once all API routes are verified on Go:

1. Set `FEATURE_COLLECTOR=true` in Go backend environment
2. Set `COLLECTOR_ENABLED=false` in Python backend environment
3. Restart both backends
4. Verify syslog events continue flowing into the database
5. Verify flow engine creates `live_flows` correctly
6. Verify pattern detection creates notifications

```bash
# In .env:
FEATURE_COLLECTOR=true

# In docker-compose, Python backend:
COLLECTOR_ENABLED=false
```

---

## Phase 3 — Full cutover

1. Set `MIGRATION_PHASE=2` — all traffic to Go
2. Monitor for 24-48 hours
3. If stable, remove Python backend from docker-compose
4. Archive Python code (tag in git, don't delete yet)

```bash
# In .env:
MIGRATION_PHASE=2

# After 48h stable:
# Remove 'backend' service from docker-compose.prod.yml
# Remove nginx python_backend upstream
```

---

## Feature flags

The Go backend has feature flags for subsystems not yet ported:

| Flag | Default | Controls |
|---|---|---|
| `FEATURE_COLLECTOR` | `false` | Syslog/NetFlow listener + flow engine |
| `FEATURE_CAUSAL_PATH` | `false` | Path analysis execution engine |
| `FEATURE_MONITOR_RUN` | `false` | Scheduled monitor execution |

When a flag is `false`, the corresponding endpoint returns:
```json
{
  "error": "feature not yet available in Go backend",
  "fallback": "use Python backend on port 8000"
}
```

---

## Rollback procedure

If the Go backend has issues at any phase:

1. Set `MIGRATION_PHASE=0` in `.env`
2. `docker compose restart nginx`
3. All traffic immediately returns to Python
4. No data loss — both backends share the same PostgreSQL

For collector rollback:
1. Set `FEATURE_COLLECTOR=false` in Go
2. Set `COLLECTOR_ENABLED=true` in Python
3. Restart both backends

---

## Data compatibility

Both backends use the same GORM/SQLAlchemy models pointing to
identical PostgreSQL tables. Key considerations:

- **Schema**: Go uses GORM AutoMigrate which is additive-only
  (adds columns, never drops). Safe to run against existing data.
- **UUIDs**: Analysis IDs are UUID strings, compatible across both.
- **Timestamps**: Both use UTC. Go uses `time.Time`, Python uses
  `datetime.utcnow()`.
- **JSON fields**: Stored as `TEXT` in PostgreSQL, parsed
  identically by both backends.
- **Password hashes**: Both use bcrypt, fully compatible.
- **JWT tokens**: Both use HS256 with the same `JWT_SECRET`,
  so tokens from one backend work on the other.
