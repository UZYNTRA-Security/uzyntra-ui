# Phase 7.10 - Production Architecture Preparation

Status: planning only. Do not deploy production, create production DNS, modify production secrets, migrate customers, commit, release, or start Phase 8 in this phase.

Phase 7.9 validated the staging custom-domain architecture:

| Staging hostname | Result |
| --- | --- |
| `staging-console.uzyntra.com` | Vercel Preview routing, TLS, HTTPS redirect, auth boundary validated |
| `staging-gateway.uzyntra.com` | Railway gateway routing through Cloudflare, TLS, HTTPS redirect, `/healthz`, `/readyz`, and admin port isolation validated |

The production plan should now copy the proven staging shape while keeping production isolated from staging, Meet, validation data, and generated test credentials.

## 1. Production Domain Mapping Plan

| Hostname | Purpose | Initial target | Phase |
| --- | --- | --- | --- |
| `console.uzyntra.com` | Customer/admin control plane, Next.js BFF, auth, RBAC, audit, analytics | Vercel Production deployment for `uzyntra-ui` | Production launch |
| `gateway.uzyntra.com` | Rust firewall data plane for protected API traffic | Railway production Rust service initially; AWS target later if enterprise networking is required | Production launch |
| `api.uzyntra.com` | Public API for future integrations and customer automation | Reserved; do not point to control plane until a separate public API contract exists | Future |
| `docs.uzyntra.com` | Documentation and API references | Docs provider or Vercel/static docs host | Future |
| `status.uzyntra.com` | Public status and incident communication | Status provider | Future |
| `auth.uzyntra.com` | Reserved identity-provider or auth-service hostname | Reserved only | Future |

Keep these separate:

| Hostname | Decision |
| --- | --- |
| `uzyntra.com` | Corporate/product site, not the Security SaaS control plane |
| `meet.uzyntra.com` | UZYNTRA Meet stack; no shared database, secrets, release gates, or runtime services |

Do not create implementation-detail public names such as `backend.uzyntra.com`, `frontend.uzyntra.com`, `database.uzyntra.com`, `postgres.uzyntra.com`, or `admin.uzyntra.com`.

## 2. Production Infrastructure Design

### Control Plane

Recommended initial provider: Vercel.

| Item | Production decision |
| --- | --- |
| Project | Prefer a dedicated production Vercel project, or a strict Production environment if project split is deferred |
| Domain | `console.uzyntra.com` |
| Runtime | Next.js App Router, Node.js runtime for database/API routes |
| Responsibilities | Sessions, RBAC, organizations, firewall inventory, API keys, security events, alerts, incidents, integrations, audit logs, BFF admin proxy |
| Protection | Production auth/RBAC inside the app; Vercel project/team MFA and least privilege |
| Rollback | Vercel deployment rollback plus DNS rollback if custom domain cutover is involved |

Production must not inherit the current Preview-global staging workaround. Before launch, either split `uzyntra-ui-production` from staging or audit every Vercel environment variable scope so staging secrets cannot be used by Production and production secrets cannot be used by Preview.

### Rust Gateway

Recommended initial provider: Railway production service.

| Item | Production decision |
| --- | --- |
| Service | Separate Railway production project/environment/service |
| Domain | `gateway.uzyntra.com` |
| Public listener | Platform `PORT`/HTTPS 443 through provider and Cloudflare |
| Admin listener | Private only; never expose raw `:9090` |
| Health checks | `/healthz` and `/readyz` over HTTPS |
| Runtime identity | Enrolled production firewall identity with production-only API key |
| Rollback | Railway deployment rollback and Cloudflare DNS rollback |

AWS target later:

- ECS/Fargate behind ALB/NLB if enterprise private networking, IAM, multi-AZ, VPC egress control, compliance, or customer availability expectations outgrow Railway.
- Do not move to AWS during the first production launch unless Railway cannot meet the required admin isolation or reliability boundary.

### Database

Recommended initial provider: Supabase Pro production project.

| Item | Production decision |
| --- | --- |
| Project | Dedicated production Supabase project, not `uzyntra-firewall-validation` and not Meet |
| Data model | Single production Postgres database initially |
| Migrations | Run from zero using repository migration command |
| Connection | Use Vercel-compatible pooled connection where appropriate |
| Backups | Enable paid-plan backups before customer data |
| Restore | Perform and document a restore drill before public customer onboarding |

Initial single database includes:

- organizations, users, sessions, memberships, roles
- firewall instances and enrollment state
- service accounts and API keys
- security events and API inventory
- alerts, incidents, notification integrations, outbox
- audit events

Future split only when scale or compliance demands it:

- analytics warehouse/read replica for heavy queries
- partitioning/retention for `security_events` and `audit_events`
- dedicated event stream if ingestion volume exceeds Postgres comfort limits

### Secret Management

Store production secrets in:

1. Vercel Production environment variables for the control plane.
2. Railway production service variables for the gateway.
3. Supabase project settings for database credentials.
4. Organization password manager or secret vault as the source-of-truth inventory.
5. AWS Secrets Manager or a dedicated secrets platform later if moving gateway/control plane into AWS.

Do not reuse:

- staging secrets
- validation database credentials
- Meet secrets
- local `.env` values
- one-time enrollment tokens after bootstrap

## 3. Environment Separation Review

| Environment | Domains | Database | Secrets | Deployments | Traffic |
| --- | --- | --- | --- | --- | --- |
| Development | `localhost`, `127.0.0.1` | Local Postgres or disposable dev DB | Local-only placeholders/dev secrets | Local Node/Rust | Developer only |
| Staging | `staging-console.uzyntra.com`, `staging-gateway.uzyntra.com` | Current validation/staging Supabase project under free-plan constraint | Staging-only Vercel/Railway variables | Vercel Preview/staging branch, Railway staging service | Internal validation only |
| Production | `console.uzyntra.com`, `gateway.uzyntra.com` | Dedicated production Supabase project | Production-only secrets | Vercel Production, Railway production service | Real customer/admin traffic |

Production isolation requirements:

- Dedicated production DB and connection string.
- Dedicated production auth/session/API-key/encryption secrets.
- Dedicated gateway admin token and control-plane service token.
- Dedicated production firewall enrollment flow.
- Dedicated production deployment targets.
- No staging Preview-global secrets promoted to production.
- No production credentials stored in repo, docs, tickets, screenshots, logs, or local shell history.

## 4. Production Security Checklist

### DNS and TLS

- Cloudflare zone ownership and MFA verified.
- `console.uzyntra.com` and `gateway.uzyntra.com` created only during an approved production DNS phase.
- Cloudflare SSL mode: Full (strict).
- TLS 1.2 minimum; TLS 1.3 enabled.
- HTTPS redirects enabled after cert issuance.
- HSTS delayed until production hostnames are stable.
- Provider verification TXT/CNAME records kept DNS-only.
- Cloudflare proxy enabled only after origin TLS and smoke tests pass.

### Control Plane

- Production auth secrets generated fresh.
- Session cookie security reviewed.
- Login rate limiting reviewed.
- RBAC roles and default permissions reviewed.
- BFF route allowlist reviewed.
- `FIREWALL_ADMIN_URL` does not expose raw admin port publicly.
- Audit logs enabled for auth, RBAC, API keys, enrollment, ingestion, alerts, incidents, integrations, and admin proxy.
- Security headers enabled and verified.

### Gateway

- Public gateway only on intended HTTPS path.
- Admin listener remains private or separately access-controlled.
- `:9090` not reachable from the internet.
- Production `FIREWALL_ADMIN_TOKEN` generated fresh.
- Production enrollment token is one-time and removed after enrollment.
- Gateway uses production firewall identity after bootstrap.
- Rate limits enabled.
- Logs redact API keys, service tokens, enrollment tokens, authorization headers, cookies, and database URLs.

### Database

- Dedicated production Supabase project created.
- Migrations applied from zero.
- Schema drift check passed.
- Backups enabled.
- Restore drill completed.
- Database access restricted to required service accounts/admins.
- RLS decision documented. If app-layer tenancy is retained, tenant isolation tests must be part of the release gate.
- Retention policy drafted for high-volume tables.

### Operations

- Vercel, Railway, Supabase, Cloudflare, GitHub MFA enabled.
- Least-privilege team roles configured.
- Break-glass access documented.
- Uptime checks configured for console, gateway, `/healthz`, `/readyz`, ingest path, and auth path.
- Error monitoring configured for Next.js and Rust.
- Incident response contacts and severity levels documented.
- Backup/restore owner assigned.
- Rollback owner assigned.

## 5. Production Deployment Runbook

This is the launch sequence to execute in a later approved production phase. Do not run these steps in Phase 7.10.

### Step 1 - Preflight

1. Confirm Phase 7.9 staging custom-domain validation is READY.
2. Freeze source commit candidates for UI and backend.
3. Confirm no uncommitted release-blocking changes.
4. Confirm production access approvals for Vercel, Railway, Supabase, Cloudflare, GitHub.
5. Confirm rollback owners and communication channel.

### Step 2 - Database Creation

1. Create dedicated Supabase production project.
2. Record project ref, region, Postgres version, and backup plan.
3. Generate production DB password.
4. Store credentials in secret vault.
5. Configure pooling strategy for Vercel runtime.
6. Run migrations from zero.
7. Run schema drift check.
8. Run tenant isolation and migration release gate tests.
9. Enable backups before customer data.
10. Perform restore drill or schedule it before public launch if provider timing blocks immediate drill.

### Step 3 - Production Secret Injection

Control plane required variables:

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
- `CONTROL_PLANE_SERVICE_TOKEN` only if machine access is required for protected production paths

Gateway required variables:

- `APP_CONFIG_PATH`
- `FIREWALL_PUBLIC_BIND_ADDR`
- `FIREWALL_ADMIN_BIND_ADDR`
- `FIREWALL_ADMIN_TOKEN`
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

Secret rules:

1. Generate production secrets fresh.
2. Inject into production environments only.
3. Do not print values.
4. Do not commit values.
5. Record only key names, owners, rotation dates, and storage location.

### Step 4 - Gateway Deployment

1. Create Railway production project/service or approved AWS equivalent.
2. Configure production gateway variables.
3. Deploy Rust gateway without production custom domain first.
4. Verify generated provider URL health:
   - `GET /healthz`
   - `GET /readyz`
5. Verify admin listener isolation.
6. Run enrollment once.
7. Disable enrollment after success.
8. Confirm telemetry disabled until control plane is ready to receive.

### Step 5 - Console Deployment

1. Configure Vercel Production environment variables.
2. Deploy production control plane without customer traffic.
3. Verify generated provider URL:
   - `GET /`
   - `GET /api/auth/me` unauthenticated -> `401`
   - invalid login -> `401`
   - BFF unauthenticated -> `401`
4. Confirm DB connectivity.
5. Confirm audit logging.
6. Confirm no staging data or staging secrets are present.

### Step 6 - Integration Validation Before DNS

1. Enable gateway telemetry against production control plane generated URL.
2. Generate one controlled test security event.
3. Verify event lands in production `security_events`.
4. Verify query and analytics endpoints.
5. Remove controlled test data if it should not remain in launch state.
6. Disable temporary validation flags.

### Step 7 - DNS Activation

1. Add `console.uzyntra.com` to Vercel production.
2. Add Vercel-required Cloudflare records.
3. Validate Vercel cert issuance.
4. Add `gateway.uzyntra.com` to Railway production.
5. Add Railway-required Cloudflare records.
6. Validate Railway cert issuance.
7. Keep DNS-only until provider validation completes.
8. Enable Cloudflare proxy only after HTTPS smoke tests pass.

### Step 8 - Production Smoke Testing

1. `https://console.uzyntra.com/` -> `200`.
2. `http://console.uzyntra.com/` redirects to HTTPS.
3. `https://console.uzyntra.com/api/auth/me` unauthenticated -> `401`.
4. Authorized user login works.
5. RBAC denies unauthorized user actions.
6. `https://gateway.uzyntra.com/healthz` -> `200`.
7. `https://gateway.uzyntra.com/readyz` -> `200`.
8. Public `:9090` remains unreachable.
9. Gateway telemetry reaches production control plane.
10. Audit logs record validation actions without secrets.

### Step 9 - Rollback

If control plane fails:

1. Revert Vercel production deployment.
2. Remove or repoint `console` DNS if routing is broken.
3. Keep production DB intact unless a migration rollback plan explicitly says otherwise.
4. Disable new customer access until smoke tests pass.

If gateway fails:

1. Roll back Railway deployment.
2. Remove or repoint `gateway` DNS.
3. Keep generated Railway URL for diagnostics.
4. Disable telemetry if it causes repeated failures.
5. Do not expose admin API to recover service.

If DNS/TLS fails:

1. Set records back to DNS-only.
2. Remove failed custom domain from provider if needed.
3. Use generated provider URLs for internal validation.
4. Retry cert issuance only after provider target records are correct.

## 6. Cost Review

Initial monthly planning estimate. Confirm live provider pricing before purchase or production launch.

| Area | Initial recommendation | Cost posture |
| --- | --- | --- |
| Vercel | Pro/team-level account for production control plane | Low to moderate; cost rises with bandwidth/functions/team seats |
| Railway | Paid production service for Rust gateway | Low to moderate; cost rises with always-on CPU/RAM/egress |
| Supabase | Pro production project | Moderate baseline; required for backups and production posture |
| Cloudflare | Free/Pro initially, depending WAF/security needs | Low initially; Pro/Business if WAF, stronger support, or advanced rules are required |
| Monitoring | UptimeRobot/Better Stack/Sentry/Logtail-style stack | Low initially; increases with retention and alert volume |
| Secret vault | 1Password/Bitwarden/team vault | Low per seat |

Expected first production shape:

- Vercel Pro for `console.uzyntra.com`.
- Railway paid service for `gateway.uzyntra.com`.
- Supabase Pro production database.
- Cloudflare DNS/TLS with WAF hardening added as needed.
- Lightweight uptime and error monitoring.

Do not launch production on free-tier assumptions if customer data or customer traffic is involved.

## 7. Remaining Risks Before Production

| Risk | Status | Required action before launch |
| --- | --- | --- |
| Staging currently reuses `uzyntra-firewall-validation` due to Supabase free-plan limit | Accepted for staging only | Create isolated production Supabase project on paid plan |
| Preview-global staging secrets exist from validation | Accepted for staging only | Ensure Production env has fresh values and Preview values cannot affect Production |
| Authenticated BFF-to-gateway custom-domain test was not completed in Phase 7.9 | Partial | Complete authenticated production preflight using a temporary authorized production user before customer access |
| Gateway production hosting target not finalized between Railway and AWS | Open | Use Railway initially unless private admin networking or customer SLA requires AWS |
| Backup restore drill not yet proven for production DB | Open | Complete restore drill before customer onboarding |
| Monitoring and incident response not wired | Open | Configure alerting and incident runbook before launch |
| Retention/partitioning for security events not configured | Open | Define initial retention and cleanup policy before real event volume |
| Cloudflare WAF/rate-limit policy not finalized | Open | Apply conservative rules after smoke tests and before customer traffic |
| Public API/docs/status/auth hostnames are reserved but not implemented | Accepted | Do not create records until services exist |

## Phase 7.10 Status

PHASE 7.10 STATUS: READY

The production architecture preparation plan is complete. No production deployment was performed, no production DNS was created, no production secrets were modified, no customers were migrated, no commits/releases were made, and Phase 8 was not started.

Recommended decision after this phase:

Choose whether Phase 8 should be production deployment execution or another enterprise-hardening phase covering monitoring, backup restore drill, WAF policy, and incident response before production launch.

