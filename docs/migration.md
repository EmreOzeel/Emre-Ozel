# Python → Go Backend Migration

Migration completed April 2026. Go backend now serves all traffic.
Python backend archived at `archive/python-backend-final/`.

---

## Phase 0 — Parallel running ✅ (April 2026)

- [x] Go backend built and running on internal port 8000
- [x] Python backend running on internal port 8000
- [x] nginx routes all traffic to Python (`MIGRATION_PHASE=0`)
- [x] `scripts/compare_backends.sh` created (supports `--body` flag)
- [x] Response shape mismatches identified and fixed
- [x] Response shape tests added (`response_shape_test.go`)

## Phase 1 — Route-by-route migration ✅ (April 2026)

- [x] `MIGRATION_PHASE=1` — migrated routes to Go, rest to Python
- [x] All 23 API endpoints verified matching between backends
- [x] JWT token compatibility fixed (Python ↔ Go)
- [x] Login response format aligned (`access_token` + `token_type`)

## Phase 2 — Full API cutover ✅ (April 2026)

- [x] `MIGRATION_PHASE=2` — all API traffic to Go
- [x] Collector migrated from Python to Go
- [x] Syslog listener (UDP+TCP on 5514) running on Go backend
- [x] Flow engine, pattern detection, retention sweeps operational
- [x] `/api/collector/status` returns live stats

## Phase 3 — Python shutdown ✅ (April 2026)

- [x] All routes verified on Go (23/23 pass)
- [x] Collector on Go (syslog + flow engine + intelligence)
- [x] Python backend removed from docker-compose
- [x] Python code archived to `archive/python-backend-final/`
- [x] nginx simplified to single Go upstream
- [x] MIGRATION_PHASE variable removed
- [x] Feature flags removed (FEATURE_COLLECTOR, FEATURE_CAUSAL_PATH, FEATURE_MONITOR_RUN)

---

## Current architecture

```
                     ┌─────────────┐
       HTTP ────────▸│    nginx    │
                     │   :80      │
                     └──────┬─────┘
                            │
                   ┌────────▼────────┐
                   │   Go Backend    │
                   │   :8000         │
                   │   + Collector   │
                   │   (5514 syslog) │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │   PostgreSQL    │
                   └─────────────────┘
```

## Data compatibility

Both backends used the same PostgreSQL tables. Key facts:

- **Schema**: Go uses GORM AutoMigrate (additive-only)
- **Password hashes**: bcrypt, fully compatible
- **JWT tokens**: HS256 with shared `JWT_SECRET`
- **Timestamps**: Both use UTC
