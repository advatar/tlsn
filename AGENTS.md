# AGENTS.md

Agent entry point for WorldMonitor. Read this first, then follow links for depth.

## Working Rules

- Always `git add` and commit after creating or editing files. Use clear, descriptive commit messages.
- Verify builds locally before claiming completion for any change.
- After assessing a request, add or update related tasks in `STATUS.md` before implementation.
- Keep going without pausing for confirmation; only ask when a decision is blocking progress.
- Never stage, commit, or alter files you did not edit for the task; leave unrelated changes for their owner.
- Other agents may be working in the same repo; mind your own business and avoid unrelated investigation or edits.
- When you have unchecked tasks, complete them one by one after passing tests, do not stop.
- When adding new functionality add unit tests.

## What This Project Is

Real-time global intelligence dashboard. TypeScript SPA (Vite + Preact) with 86 panel components, 60+ Vercel Edge API endpoints, a Tauri desktop app with Node.js sidecar, and a Railway relay service. Aggregates 30+ external data sources (geopolitics, military, finance, climate, cyber, maritime, aviation).

## Repository Map

```text
.
├── src/                    # Browser SPA (TypeScript, class-based components)
│   ├── app/                # App orchestration (data-loader, refresh-scheduler, panel-layout)
│   ├── components/         # 86 UI panels + map components (Panel subclasses)
│   ├── config/             # Variant configs, panel/layer definitions, market symbols
│   ├── services/           # Business logic (120+ service files, organized by domain)
│   ├── types/              # TypeScript type definitions
│   ├── utils/              # Shared utilities (circuit-breaker, theme, URL state, DOM)
│   ├── workers/            # Web Workers (analysis, ML/ONNX, vector DB)
│   ├── generated/          # Proto-generated client/server stubs (DO NOT EDIT)
│   ├── locales/            # i18n translation files
│   └── App.ts              # Main application entry
├── api/                    # Vercel Edge Functions (plain JS, self-contained)
│   ├── _*.js               # Shared helpers (CORS, rate-limit, API key, relay)
│   ├── health.js           # Health check endpoint
│   ├── bootstrap.js        # Bulk data hydration endpoint
│   └── <domain>/           # Domain-specific endpoints (aviation/, climate/, etc.)
├── server/                 # Server-side shared code (used by Edge Functions)
│   ├── _shared/            # Redis, rate-limit, LLM, caching, response headers
│   ├── gateway.ts          # Domain gateway factory (CORS, auth, cache tiers)
│   ├── router.ts           # Route matching
│   └── worldmonitor/       # Domain handlers (mirrors proto service structure)
├── proto/                  # Protobuf definitions (sebuf framework)
│   ├── buf.yaml            # Buf configuration
│   └── worldmonitor/       # Service definitions with HTTP annotations
├── shared/                 # Cross-platform data (JSON configs for markets, RSS domains)
├── scripts/                # Seed scripts, build helpers, data fetchers
├── src-tauri/              # Tauri desktop shell (Rust + Node.js sidecar)
│   └── sidecar/            # Node.js sidecar API server
├── tests/                  # Unit/integration tests (node:test runner)
├── e2e/                    # Playwright E2E specs
├── docs/                   # Mintlify documentation site
├── docker/                 # Docker build for Railway services
├── deploy/                 # Deployment configs
└── blog-site/              # Static blog (built into public/blog/)
```

## How to Run

```bash
npm install              # Install deps (also runs blog-site postinstall)
npm run dev              # Start Vite dev server (full variant)
npm run dev:tech         # Start tech-only variant
npm run typecheck        # tsc --noEmit (strict mode)
npm run typecheck:api    # Typecheck API layer separately
npm run test:data        # Run unit/integration tests
npm run test:sidecar     # Run sidecar + API handler tests
npm run test:e2e         # Run all Playwright E2E tests
make generate            # Regenerate proto stubs (requires buf + sebuf plugins)
```

## Architecture Rules

### Dependency Direction

```text
types -> config -> services -> components -> app -> App.ts
```

- `types/` has zero internal imports
- `config/` imports only from `types/`
- `services/` imports from `types/` and `config/`
- `components/` imports from all above
- `app/` orchestrates components and services

### API Layer Constraints

- `api/*.js` are Vercel Edge Functions: self-contained JS only.
- They cannot import from `../src/` or `../server/` because those ship in a different runtime.
- Only same-directory `_*.js` helpers and npm packages are allowed.
- Enforced by `tests/edge-functions.test.mjs` and the pre-push esbuild check.

### Server Layer

- `server/` code is bundled into Edge Functions at deploy time via the gateway.
- `server/_shared/` contains Redis client, rate limiting, LLM helpers.
- `server/worldmonitor/<domain>/` has RPC handlers matching proto services.
- All handlers use `cachedFetchJson()` for Redis caching with stampede protection.

### Proto Contract Flow

```text
proto/ definitions -> buf generate -> src/generated/{client,server}/ -> handlers wire up
```

- GET fields need `(sebuf.http.query)` annotation.
- `repeated string` fields need `parseStringArray()` in the handler.
- `int64` maps to `string` in TypeScript.
- CI checks proto freshness via `.github/workflows/proto-check.yml`.

## Variant System

The app ships multiple variants with different panel and layer configurations:

- `full` (default): All features
- `tech`: Technology-focused subset
- `finance`: Financial markets focus
- `commodity`: Commodity markets focus
- `happy`: Positive news only

Variant is set via `VITE_VARIANT` and lives in `src/config/variants/`.

## Key Patterns

### Adding a New API Endpoint

1. Define the proto message in `proto/worldmonitor/<domain>/`.
2. Add the RPC with `(sebuf.http.config)` annotation.
3. Run `make generate`.
4. Create the handler in `server/worldmonitor/<domain>/`.
5. Wire the handler in that domain's `handler.ts`.
6. Use `cachedFetchJson()` for caching and include request-varying params in the cache key.

### Adding a New Panel

1. Create `src/components/MyPanel.ts` extending `Panel`.
2. Register it in `src/config/panels.ts`.
3. Add it to the variant configs in `src/config/variants/`.
4. Wire data loading in `src/app/data-loader.ts`.

### Circuit Breakers

- `src/utils/circuit-breaker.ts` handles client-side breakers.
- Use separate breakers per data domain to prevent cascade failures.

### Caching

- Redis (Upstash) via `server/_shared/redis.ts`
- `cachedFetchJson()` coalesces concurrent cache misses
- Cache tiers: fast (5m), medium (10m), slow (30m), static (2h), daily (24h)
- Cache keys must include request-varying params

## Testing

- Unit and integration tests: `tests/*.test.{mjs,mts}` using `node:test`
- Sidecar tests: `api/*.test.mjs`, `src-tauri/sidecar/*.test.mjs`
- E2E: `e2e/*.spec.ts` using Playwright
- Visual regression: golden screenshot comparisons per variant

## CI Checks

| Workflow | Trigger | What it checks |
| --- | --- | --- |
| `typecheck.yml` | PR + push to `main` | `tsc --noEmit` for `src` and API |
| `lint.yml` | PR (markdown changes) | `markdownlint-cli2` |
| `proto-check.yml` | PR (proto changes) | Generated code freshness |
| `build-desktop.yml` | Manual | Tauri desktop build |
| `test-linux-app.yml` | Manual | Linux AppImage smoke test |

## Pre-Push Hook

Runs automatically before `git push`:

1. TypeScript check for `src` and API
2. CJS syntax validation
3. Edge function esbuild bundle check
4. Edge function import guardrail test
5. Markdown lint
6. MDX lint for Mintlify compatibility
7. Version sync check

## Deployment

- Web: Vercel auto-deploys on push to `main`
- Relay and seeds: Railway via Docker and cron services
- Desktop: Tauri builds via GitHub Actions
- Docs: Mintlify proxied through Vercel at `/docs`

## Critical Conventions

- `fetch.bind(globalThis)` is banned; use `(...args) => globalThis.fetch(...args)` instead.
- Edge Functions cannot use `node:http`, `node:https`, or `node:zlib`.
- Always include a `User-Agent` header in server-side fetch calls.
- Yahoo Finance requests must be staggered by 150 ms.
- New data sources must wire bootstrap hydration in `api/bootstrap.js`.
- Redis seed scripts must write `seed-meta:<key>` for health monitoring.

## External References

- [Architecture (system reference)](ARCHITECTURE.md)
- [Design philosophy](docs/architecture.mdx)
- [Contributing guide](CONTRIBUTING.md)
- [Data sources catalog](docs/data-sources.mdx)
- [Health endpoints](docs/health-endpoints.mdx)
- [Adding endpoints guide](docs/adding-endpoints.mdx)
- [API reference (OpenAPI)](docs/api/)
