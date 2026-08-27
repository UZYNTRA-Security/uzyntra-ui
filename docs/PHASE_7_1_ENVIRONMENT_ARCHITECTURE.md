# Phase 7.1 - Production Environment Architecture

Status: planning only. No deployment, infrastructure creation, commits, or pushes.

Released baseline:

- Backend: `phase-6-alerts-integrations` at `40b479468232c4496f4505e7bf9a343b1f31ce97`
- UI/control plane: `phase-6-alerts-integrations` at `8884e4786d5c5b9d6ba3ac5884058546e1532986`

## 1. Recommended Production Architecture

UZYNTRA should be operated as two separate products/environments:

- UZYNTRA Security SaaS: `console.uzyntra.com`, `gateway.uzyntra.com`, security control-plane Postgres.
- UZYNTRA Meet: `meet.uzyntra.com`, its own Vercel/Supabase/LiveKit stack.

Do not share databases, service accounts, runtime secrets, dashboards, or release gates between Meet and the Security SaaS.

Recommended security SaaS production shape:

```text
Operators / customers
  |
  | HTTPS
  v
console.uzyntra.com
  |
  v
Vercel - Next.js control plane / BFF
  |
  | server-side only: auth, RBAC, audit, ingestion, admin proxy
  v
Supabase Postgres - control plane DB

Protected API traffic
  |
  | HTTPS
  v
gateway.uzyntra.com
  |
  v
Rust API Firewall gateway
  |
  v
Customer origin APIs

Rust gateway telemetry
  |
  | service account API key
  v
https://console.uzyntra.com/api/ingest/security-events
```

The Rust admin API must not be treated as a normal public API. The preferred enterprise design is a private or access-controlled admin path from the Next.js BFF to the Rust gateway. If Vercel and the Rust host cannot share private networking initially, place the admin API behind Cloudflare Access or equivalent service-token protection, keep the Rust `FIREWALL_ADMIN_TOKEN`, and apply request allowlisting/rate limiting.

## 2. Environment Model

### Development

- Database: local Postgres or disposable Supabase development project. Never use staging or production data by default.
- Secrets: local `.env.local` / shell env only; use placeholders or generated dev-only secrets. Never store live credentials in git.
- Domains: `localhost:3000` for UI; `127.0.0.1:8080` public gateway; `127.0.0.1:9090` admin API.
- Deployment platform: local Node/Next.js and local Rust process.
- Logging: console logs, local database audit records, local Rust logs.
- Access control: local developer machine only; development users and API keys.

### Staging

- Database: dedicated staging Supabase project, for example `uzyntra-security-staging`.
- Secrets: Vercel Preview/Custom Environment secrets for UI; Railway/Fly/Render/AWS service variables for Rust; no production secrets.
- Domains: `staging-console.uzyntra.com`, `staging-gateway.uzyntra.com`; optional `staging-api.uzyntra.com` only when a public SaaS API exists.
- Deployment platform: Vercel custom `staging` environment or branch-specific preview for UI; separate Rust staging service/project.
- Logging: provider logs plus application audit logs; alerting can be lower-severity than production.
- Access control: internal team only; Cloudflare Access or Vercel protection; staging tenants seeded with synthetic data.

### Production

- Database: dedicated production Supabase Pro/Team project or managed Postgres equivalent. Enable backups and define restore procedure before launch.
- Secrets: production-only secrets stored in hosting provider secret stores and an organization password manager or centralized secret manager.
- Domains: `console.uzyntra.com`, `gateway.uzyntra.com`, future `api.uzyntra.com`, `docs.uzyntra.com`, `status.uzyntra.com`.
- Deployment platform: Vercel production for UI; Railway Pro initially for Rust gateway, with AWS ECS/Fargate as the later enterprise target.
- Logging: application audit logs, provider logs, uptime checks, error monitoring, and incident alerting.
- Access control: least-privilege GitHub, Vercel, database, DNS, and hosting roles; MFA required; break-glass account documented.

## 3. Domain Decisions

Use service-role names, not repository or infrastructure names.

| Hostname | Decision | Purpose |
| --- | --- | --- |
| `uzyntra.com` | Keep | Corporate/product site |
| `meet.uzyntra.com` | Keep separate | UZYNTRA Meet product |
| `console.uzyntra.com` | Use | Security SaaS dashboard and BFF |
| `gateway.uzyntra.com` | Use | Rust firewall data plane / protected traffic gateway |
| `api.uzyntra.com` | Reserve | Future public UZYNTRA SaaS/developer API |
| `docs.uzyntra.com` | Reserve | Product documentation |
| `status.uzyntra.com` | Reserve | Public status page |

Avoid `frontend`, `backend`, `database`, `postgres`, `internal`, and `admin` as public hostnames. They expose implementation detail and are poor enterprise product names.

DNS posture:

- Use Cloudflare as the DNS/security front door if the domain is already managed there.
- Proxy HTTP(S) records where compatible, especially `console` and `gateway`.
- Keep provider verification CNAME/TXT records DNS-only when the provider requires it.
- Do not create DNS records until Vercel/Rust hosting gives exact targets.

## 4. Hosting Decisions

### Next.js Control Plane

Recommendation: Vercel.

Why:

- Best fit for the existing Next.js App Router project.
- Native Production/Preview/Development environment model.
- Encrypted environment variables.
- Fast rollback and preview workflow.
- Reasonable initial cost on Pro, with Enterprise path for stronger access control and SLA.

Staging should use either Vercel Pro custom environment `staging` or a branch-specific preview with staging secrets.

### Rust Firewall Gateway

Initial recommendation: Railway Pro for first production hardening pass.

Why:

- Simple GitHub/container deployment path for a Rust HTTP service.
- Health checks, custom domains, service variables, rollbacks, log retention, and usage-based pricing.
- Lower operational burden than AWS while the product is still early.

Risk:

- The current Rust process exposes both public proxy and admin API binds. Production must ensure the admin API is private or access-controlled.
- If customers depend on gateway availability, move from a single service to multiple replicas and define region/rollback behavior.

Enterprise target: AWS ECS/Fargate behind ALB/NLB, or Fly.io if edge/regional proximity becomes a primary requirement.

Provider notes:

- Railway: best immediate Rust deployment ergonomics and cost/simplicity balance.
- Fly.io: good for region-aware gateway placement; more ops complexity.
- Render: good managed web service ergonomics, but less compelling than Railway for this specific Rust gateway MVP.
- AWS ECS/Fargate: strongest enterprise control, IAM, private networking, and compliance path; higher setup and operations burden.
- AWS App Runner: do not select for new architecture; AWS documentation says App Runner is no longer open to new customers starting March 31, 2026.

### Database

Initial recommendation: Supabase Pro production project for control-plane Postgres.

Why:

- Existing project already uses Postgres + Drizzle.
- Fast setup, backups on paid plans, connection pooling, dashboard, and SQL tooling.
- Keeps Phase 7 focused on production readiness rather than operating Postgres infrastructure.

Enterprise target: Supabase Team/Enterprise or AWS RDS/Aurora PostgreSQL if compliance, VPC isolation, audit controls, or custom backup policies require it.

## 5. Secret Model

Production secrets must be unique per environment. Do not reuse dev, staging, validation, Meet, or release-gate credentials.

### UI / Control Plane

Required:

- `DATABASE_URL`
- `DATABASE_POOL_SIZE`
- `AUTH_PASSWORD_PEPPER`
- `AUTH_SESSION_SECRET`
- `AUTH_API_KEY_SECRET`
- `AUTH_MANAGEMENT_TOKEN_SECRET`
- `INTEGRATION_SECRET_ENCRYPTION_KEY`
- `FIREWALL_ADMIN_URL`
- `FIREWALL_ADMIN_TOKEN`
- `BFF_ADMIN_TIMEOUT_MS`
- `BFF_MAX_BODY_BYTES`

Storage:

- Vercel environment variables for runtime.
- Separate values for Development, Staging, Production.
- Backup copy in 1Password/Bitwarden/organization vault with restricted access.
- For enterprise AWS migration, store canonical values in AWS Secrets Manager or a dedicated secrets platform and sync into runtime.

### Rust Firewall Gateway

Required:

- `APP_CONFIG_PATH`
- `FIREWALL_PUBLIC_BIND_ADDR`
- `FIREWALL_ADMIN_BIND_ADDR`
- `FIREWALL_ADMIN_TOKEN`
- `FIREWALL_API_KEYS`
- `UPSTREAM_BASE_URL`
- `RUST_LOG`
- `UZYNTRA_CONTROL_PLANE_TELEMETRY_ENABLED`
- `UZYNTRA_CONTROL_PLANE_INGEST_URL`
- `UZYNTRA_CONTROL_PLANE_API_KEY`
- `UZYNTRA_FIREWALL_INSTANCE_ID`
- `UZYNTRA_CONTROL_PLANE_ENROLLMENT_ENABLED`
- `UZYNTRA_CONTROL_PLANE_ENROLLMENT_URL`
- `UZYNTRA_CONTROL_PLANE_ENROLLMENT_TOKEN`
- `UZYNTRA_CONTROL_PLANE_INSTALLATION_IDENTIFIER`
- `UZYNTRA_CONTROL_PLANE_HOSTNAME`
- `UZYNTRA_CONTROL_PLANE_VERSION`
- `UZYNTRA_CONTROL_PLANE_REGION`

Storage:

- Rust host service variables/secrets for runtime.
- Enrollment token should be short-lived and removed after enrollment.
- Service account API key should be rotated after incidents and on a planned cadence.
- Gateway admin token should be long random material, not shared with telemetry API keys.

## 6. Network Design

Public traffic:

```text
Customer API clients
  -> HTTPS 443 gateway.uzyntra.com
  -> Rust public listener, platform PORT mapped to internal 8080
  -> customer upstream API
```

Control plane:

```text
Browser
  -> HTTPS 443 console.uzyntra.com
  -> Vercel Next.js BFF
  -> Supabase Postgres
```

Telemetry:

```text
Rust gateway
  -> HTTPS 443 console.uzyntra.com/api/ingest/security-events
  -> service account API key auth
  -> Postgres security_events
```

Admin command path:

```text
Vercel Next.js BFF
  -> protected admin route to Rust gateway
  -> Rust admin listener, currently internal 9090 conceptually
```

Production rule: do not expose raw `:9090` to the public internet. If platform constraints require an HTTPS admin URL, it should be behind Cloudflare Access/service-token policy or equivalent, require `FIREWALL_ADMIN_TOKEN`, rate limit requests, log all admin calls, and use a separate hostname from `gateway.uzyntra.com`.

Public ports:

- `443` for `console.uzyntra.com`
- `443` for `gateway.uzyntra.com`
- Future `443` for `api.uzyntra.com`, `docs.uzyntra.com`, `status.uzyntra.com`

Private/internal ports:

- Rust public listener internal target: `8080` or provider `PORT`
- Rust admin listener internal target: `9090`, private/access-controlled only
- Postgres: provider-managed; not publicly browsable

## 7. Database Strategy

Initial production recommendation: one dedicated production Postgres database for the UZYNTRA Security SaaS control plane.

Use one DB initially for:

- organizations, users, sessions, RBAC
- firewall inventory and enrollment
- API keys and service accounts
- security events
- API inventory
- alerts, incidents, notification outbox
- audit events

Reasoning:

- Current Drizzle schema is cohesive and transactional.
- Tenant isolation is application-enforced through organization/firewall IDs.
- Operational simplicity matters more than premature database split.

Hardening path:

- Add table partitioning or retention policies for `security_events`, `audit_events`, and notification delivery history.
- Add read replica or analytics warehouse when dashboard/analytics workload threatens transactional latency.
- Keep the Rust gateway local runtime store separate from control-plane Postgres unless a future design explicitly replaces it.
- Never share the Meet database with the security platform.

Staging and production must be separate projects/databases. Production backups must be tested with a restore drill before public launch.

## 8. Production Security Checklist

- TLS enabled for every public hostname.
- HSTS after domain stability is confirmed.
- No secrets in git, browser code, logs, screenshots, build artifacts, or issue text.
- Unique production secrets; no validation/staging reuse.
- Rotate enrollment tokens and service-account API keys.
- Restrict admin API with private networking or access gateway plus `FIREWALL_ADMIN_TOKEN`.
- Enforce Vercel/Railway/Supabase/GitHub MFA.
- Least-privilege access for GitHub, Vercel, Supabase, DNS, hosting, and releases.
- Backups enabled and restore tested.
- PITR decision documented for production Postgres.
- Uptime checks for `console`, `gateway`, ingest API, and gateway health/readiness.
- Error tracking for Next.js API routes and Rust runtime.
- Log retention policy for provider logs and application audit logs.
- Rate limits for login, ingestion, admin proxy, alert-rule writes, and webhook delivery.
- Audit log immutability policy and retention target.
- Security headers for console.
- Webhook SSRF controls maintained and tested.
- Production incident response runbook.
- Rollback procedure for UI, Rust gateway, migrations, and DNS.

## 9. Migration Plan

1. Freeze released Phase 6 source as baseline.
2. Create separate staging and production environment inventories.
3. Generate production/staging secret values offline.
4. Create staging database and run migrations from zero.
5. Configure Vercel staging environment variables.
6. Configure Rust staging service variables without exposing the admin API publicly.
7. Run staging release gate: auth, RBAC, ingestion, alerting, notification outbox, telemetry, admin proxy, build.
8. Create production database only after staging passes.
9. Apply production migrations from zero.
10. Configure production secrets.
11. Deploy UI and Rust services in production.
12. Attach domains and TLS after service health is proven.
13. Enable observability, uptime checks, backups, and incident alerts.
14. Run production release gate.

## 10. Deployment Order

No deployment in Phase 7.1. Recommended future order:

1. Environment decision record.
2. Staging Supabase project.
3. Staging Vercel project/environment.
4. Staging Rust gateway service.
5. Staging DNS only after platform targets are known.
6. Staging release gate.
7. Production Supabase project with backup policy.
8. Production Vercel project/environment.
9. Production Rust gateway service.
10. Production DNS/TLS.
11. Observability and alert routing.
12. Production release gate.

## 11. Source Notes

Official docs checked during Phase 7.1 planning:

- Vercel environment variables and environments: `https://vercel.com/docs/environment-variables`, `https://vercel.com/docs/deployments/environments`
- Vercel pricing: `https://vercel.com/pricing`
- Railway pricing/deployment features: `https://railway.com/pricing`
- Fly.io resource pricing: `https://fly.io/docs/about/pricing/`
- Render pricing/custom domains/web services: `https://render.com/pricing`, `https://render.com/docs/custom-domains`, `https://render.com/docs/web-services`
- Supabase pricing/backups: `https://supabase.com/pricing`, `https://supabase.com/docs/guides/platform/backups`
- Cloudflare DNS proxy guidance: `https://developers.cloudflare.com/dns/proxy-status/`
- AWS App Runner availability/custom domains and AWS Secrets Manager: `https://docs.aws.amazon.com/apprunner/latest/dg/apprunner-availability-change.html`, `https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html`
