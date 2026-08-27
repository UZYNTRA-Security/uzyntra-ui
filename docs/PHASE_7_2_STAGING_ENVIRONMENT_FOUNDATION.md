# Phase 7.2 - Staging Environment Foundation

Status: documentation only. Do not deploy production, create production resources, connect production domains, start Phase 8, commit, push, tag, or release.

Released baseline:

- Backend: `phase-6-alerts-integrations` at `40b479468232c4496f4505e7bf9a343b1f31ce97`
- UI/control plane: `phase-6-alerts-integrations` at `8884e4786d5c5b9d6ba3ac5884058546e1532986`

Scope: UZYNTRA Security SaaS only. UZYNTRA Meet remains separate on `meet.uzyntra.com` with its own Supabase and LiveKit stack.

## 1. Staging Architecture

Staging should mirror the production shape without using production credentials, production data, or production domains.

```text
Internal operators / QA
  |
  | HTTPS
  v
staging-console.uzyntra.com
  |
  v
Vercel - uzyntra-ui staging environment
  |
  | server-side auth, RBAC, audit, ingestion, admin proxy
  v
Supabase - dedicated staging Postgres project

Synthetic protected API traffic
  |
  | HTTPS
  v
staging-gateway.uzyntra.com
  |
  v
Railway - dedicated Rust staging service/project
  |
  v
Synthetic upstream API / test origin

Rust telemetry
  |
  | service-account API key
  v
https://staging-console.uzyntra.com/api/ingest/security-events
```

Staging must prove deployability and operational safety before production exists. It should not be a disposable validation DB and should not reuse the previous `uzyntra-firewall-validation` Supabase project.

## 2. Required Accounts And Resources

### UI Staging

- Provider: Vercel.
- Project: `uzyntra-ui`.
- Environment: `staging`.
- Strategy:
  - Preferred: Vercel Pro custom environment named `staging`.
  - Acceptable fallback: branch-specific Preview deployment for a `staging` branch with staging-only Preview variables.
- Git source: released Phase 6 UI commit `8884e4786d5c5b9d6ba3ac5884058546e1532986`.
- Access: internal team only. Use Vercel team permissions and deployment protection where available.

### Rust Staging

- Provider: Railway, matching the Phase 7.1 initial recommendation.
- Project/service: separate Railway project or clearly separated environment, for example `uzyntra-security-staging`.
- Git source: released Phase 6 backend commit `40b479468232c4496f4505e7bf9a343b1f31ce97`.
- Runtime: Rust gateway service with one staging replica initially.
- Upstream: synthetic staging origin, not a production customer API.
- Access: admin API must be private or protected before any external testing.

### Database Staging

- Provider: Supabase.
- Project: new dedicated staging project, for example `uzyntra-security-staging`.
- Database: PostgreSQL managed by Supabase.
- Region: choose the same region family intended for production unless latency or cost testing requires a different staging region.
- Access: least-privilege project access; MFA required for human access.
- Data: synthetic tenant/user/firewall data only.

## 3. Staging Domains

Do not create DNS records yet. Add records only after Vercel and Railway provide exact targets.

| Hostname | Provider | Target | Purpose |
| --- | --- | --- | --- |
| `staging-console.uzyntra.com` | Cloudflare DNS -> Vercel | Exact Vercel-assigned CNAME/verification records, TBD | Internal staging control plane |
| `staging-gateway.uzyntra.com` | Cloudflare DNS -> Railway | Exact Railway custom-domain target, TBD | Staging Rust gateway public data plane |

DNS rules:

- Keep provider verification records DNS-only if required.
- Proxy web traffic through Cloudflare when compatible with Vercel/Railway custom-domain requirements.
- Do not create `staging-api.uzyntra.com` until a separate public SaaS API exists.
- Do not point `console.uzyntra.com`, `gateway.uzyntra.com`, or any production hostname at staging resources.

## 4. Required Environment Variables

All values must be staging-only. Do not reuse production, validation, Meet, or local development secrets.

### Vercel Staging Variables

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

Recommended staging values:

- `DATABASE_POOL_SIZE=10` initially.
- `BFF_ADMIN_TIMEOUT_MS=10000`.
- `BFF_MAX_BODY_BYTES=1048576`.
- `FIREWALL_ADMIN_URL` should target a protected staging admin endpoint, not the public gateway path.
- `INTEGRATION_SECRET_ENCRYPTION_KEY` must decode to 32 bytes; prefer 64 hex characters generated for staging only.

Do not set sensitive values as `NEXT_PUBLIC_*`.

### Rust Staging Variables

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

Recommended staging values:

- `RUST_LOG=info`.
- `UZYNTRA_CONTROL_PLANE_TELEMETRY_ENABLED=true` after staging enrollment succeeds.
- `UZYNTRA_CONTROL_PLANE_INGEST_URL=https://staging-console.uzyntra.com/api/ingest/security-events`.
- `UZYNTRA_CONTROL_PLANE_ENROLLMENT_URL=https://staging-console.uzyntra.com/api/firewalls/enroll`.
- `UZYNTRA_CONTROL_PLANE_HOSTNAME=staging-gateway.uzyntra.com`.
- `UZYNTRA_CONTROL_PLANE_VERSION=phase-6-alerts-integrations`.
- `UZYNTRA_CONTROL_PLANE_REGION=<staging-region>`.

Enrollment token handling:

- Generate in staging console only.
- Use once during gateway enrollment.
- Remove `UZYNTRA_CONTROL_PLANE_ENROLLMENT_TOKEN` after successful enrollment if the platform permits.

## 5. Deployment Prerequisites

No deployment occurs in this phase. Before Phase 7.3 or 7.4 can begin, these must exist:

- Supabase staging project created.
- Supabase staging connection string available to Vercel staging only.
- Vercel `uzyntra-ui` project linked to GitHub.
- Vercel staging environment or branch-specific Preview variable strategy selected.
- Railway staging project/service planned with custom domain disabled until health passes.
- Staging secret inventory generated and stored in the organization vault.
- Cloudflare zone access confirmed, but DNS records not created.
- Synthetic upstream API selected for Rust gateway testing.
- Staging release gate checklist accepted.

## 6. Migration Checklist

Database preparation:

- Create a new Supabase staging project.
- Confirm PostgreSQL version and region.
- Confirm connection mode:
  - Direct connection for long-lived migration/admin operations.
  - Pooler connection for serverless Vercel runtime if appropriate.
- Enable daily backups if plan supports it.
- Decide whether staging needs PITR; usually no for early staging, yes if staging becomes customer-demo critical.
- Store credentials in the vault and provider secret stores only.

Migration execution:

- Run `npm run db:migrate` from released Phase 6 UI source.
- Confirm all migrations from `0000` through `0011` apply from zero.
- Confirm `drizzle.__drizzle_migrations` contains the expected migration count.
- Confirm Phase 6 tables exist:
  - `alert_rules`
  - `alert_suppressions`
  - `alerts`
  - `incidents`
  - `incident_alerts`
  - `notification_channels`
  - `notification_deliveries`
  - `scheduled_reports`
- Run `npm run db:generate` and confirm no schema drift.
- Seed synthetic organization, user, membership, role, firewall, service account, and API key data.
- Run tenant isolation checks:
  - organization A cannot read organization B alerts/events.
  - firewall A cannot be selected from organization B.
  - Viewer cannot manage alerts or integrations.
  - Owner can manage alert rules and integrations.
- Run Phase 6 staging tests against staging DB:
  - alert rule creation
  - security event ingestion
  - alert dedupe
  - threshold windows
  - incident lifecycle
  - notification outbox
  - webhook signing/encryption
  - audit event persistence

## 7. Rust Staging Health Checks

Required public health/readiness:

- `GET https://staging-gateway.uzyntra.com/healthz`
- `GET https://staging-gateway.uzyntra.com/readyz`

Admin health:

- Admin API health checks should be reachable only from the approved admin path.
- If private networking is unavailable, protect admin endpoint with Cloudflare Access/service token or equivalent, plus `FIREWALL_ADMIN_TOKEN`.

Runtime expectations:

- Public listener binds to the provider-required host/port.
- Admin listener is not exposed as a raw public port.
- Telemetry delivery uses staging service account API key.
- Logs must never include admin tokens, API keys, enrollment tokens, authorization headers, cookies, or secret values.

## 8. Staging Security Checklist

- Separate Supabase project from validation, development, Meet, and future production.
- Separate Vercel staging variables.
- Separate Railway staging secrets.
- Separate staging domains.
- No production values reused.
- No validation DB credentials reused.
- MFA enabled for GitHub, Vercel, Supabase, Railway, and Cloudflare.
- Least-privilege access for all platforms.
- Backups enabled where plan supports it.
- HTTPS ready before browser testing.
- Audit logging enabled and verified.
- Admin API not public.
- Telemetry uses service account API key.
- Enrollment token one-time and removed after use.
- Staging data synthetic only.
- Secret scan before any future commit.
- No secrets in screenshots, docs, issue comments, logs, or terminal captures.

## 9. Staging Release Gate

Before production preparation, staging must pass:

- UI build on Vercel staging.
- Rust gateway build/deploy health.
- Supabase migration from zero.
- `npm run db:generate` no drift.
- Auth login/logout/session checks.
- RBAC checks.
- API key lifecycle checks.
- Security event ingestion checks.
- Alert creation/dedupe/threshold checks.
- Incident lifecycle checks.
- Notification outbox checks.
- Webhook security/encryption checks.
- Audit persistence checks.
- Admin proxy path check from BFF to Rust gateway.
- Rust telemetry delivery to staging console.
- Gateway health/readiness checks.
- Secret/artifact scan.

## 10. Stop Condition

Stop after this document until explicitly instructed to create staging resources.

The next operational steps, only after approval, are:

1. Create Supabase staging project.
2. Configure Vercel staging environment.
3. Create Railway staging Rust service.
4. Deploy staging UI.
5. Deploy staging Rust gateway.
6. Configure staging DNS/TLS.
7. Run staging release gate.
