# Phase 7.11 - Production Hardening and Operational Readiness

Status: documentation and validation planning only. Do not deploy production, create production DNS, create production secrets, migrate production data, commit, release, or start Phase 8 in this phase.

Phase 7.9 proved staging custom domains. Phase 7.10 prepared the production architecture. Phase 7.11 defines the operational controls required before a security SaaS launch: monitoring, backup recovery, edge policy, incident response, secret rotation, production security validation, and risk ownership.

## 1. Monitoring and Observability Plan

Production monitoring must cover both service availability and security-relevant behavior.

### Availability Metrics

| Area | Metric | Target/alert condition |
| --- | --- | --- |
| Control plane | `https://console.uzyntra.com/` availability | Alert after 2 consecutive failures |
| Control plane auth | `/api/auth/me` unauthenticated response | Expected `401`; alert on `5xx` or timeout |
| Gateway health | `https://gateway.uzyntra.com/healthz` | Expected `200`; alert after 2 consecutive failures |
| Gateway readiness | `https://gateway.uzyntra.com/readyz` | Expected `200`; alert if not ready for 2 checks |
| DNS/TLS | certificate expiry | Warn at 30 days, critical at 7 days |
| Admin exposure | public `:9090` reachability | Critical if reachable |

### Performance Metrics

| Area | Metric | Initial threshold |
| --- | --- | --- |
| Control-plane API | p95 latency | Warn above 1s, critical above 3s |
| Gateway proxy | p95 upstream/proxy latency | Warn above expected upstream baseline + 500ms |
| Database | connection usage | Warn above 70%, critical above 85% |
| Database | slow queries | Warn for repeated queries above 1s |
| Ingestion | security event ingest latency | Warn above 2s p95 |
| Alert delivery | outbox retry backlog | Warn on sustained growth for 15 minutes |

### Error and Security Metrics

| Signal | Alert condition |
| --- | --- |
| Next.js `5xx` rate | sustained rate above baseline for 5 minutes |
| Rust gateway error rate | sustained rate above baseline for 5 minutes |
| ingestion failures | spike in `401`, `403`, or `5xx` |
| API key auth failures | spike by organization, key prefix, or source IP |
| login failures | spike by email, organization, source IP, or ASN |
| WAF blocks/challenges | sudden increase after rule change |
| alert delivery failures | repeated delivery failures by channel |
| audit event write failures | any repeated failure |

### Log Retention Strategy

| Source | Retention target | Notes |
| --- | --- | --- |
| Vercel logs | 14-30 days minimum | Export if provider retention is shorter than incident needs |
| Railway logs | 14-30 days minimum | Include gateway startup, health, telemetry worker, detection summaries |
| Supabase logs | plan-dependent minimum | Retain database/auth/query diagnostics within provider limits |
| Application audit logs | 180 days minimum initial target | Keep in Postgres initially; define archival before scale |
| Security events | 90 days hot data initial target | Define retention/partitioning before heavy production traffic |
| Incident records | 1 year minimum | Keep response history and postmortems |

Logs must not contain database URLs, API keys, service tokens, enrollment tokens, session cookies, password hashes, authorization headers, Vercel bypass secrets, or webhook signing secrets.

### Security Event Monitoring

Monitor:

- high/critical security events by organization and firewall.
- detection spikes by detector ID.
- repeated blocked requests from one source.
- API route discovery anomalies.
- telemetry delivery lag.
- missing telemetry from an enrolled production gateway.
- security event ingestion `403` for firewall ownership mismatch.

Initial tooling can be lightweight:

- Vercel and Railway provider logs.
- Supabase dashboard/logs.
- Uptime service for public endpoints.
- Sentry or equivalent for Next.js and Rust errors.
- Existing Phase 6 alerts for internal security-event and incident workflows.

## 2. Backup and Disaster Recovery Plan

### Supabase Production Backup Strategy

Production database must be a dedicated paid Supabase project before customer data.

Requirements:

- Automated backups enabled before launch.
- Backup schedule and retention documented.
- PITR decision documented before onboarding customers.
- Database region recorded.
- Restore owner assigned.
- Backup health checked weekly.

Do not rely on staging `uzyntra-firewall-validation` backup behavior for production assumptions.

### Restore Procedure

1. Declare recovery event and assign incident commander.
2. Freeze writes if data corruption is suspected.
3. Identify restore point based on incident timeline.
4. Restore into a separate recovery project/database first when possible.
5. Validate schema version and migration journal.
6. Validate tenant counts, users, firewalls, API keys, security events, alerts, incidents, and audit events.
7. Run read-only application smoke tests against recovery database.
8. Decide cutover or targeted data repair.
9. Record recovery timeline, data loss window, and customer impact.
10. Rotate credentials if compromise is suspected.

### RPO and RTO Targets

| Tier | Initial target |
| --- | --- |
| RPO | 24 hours maximum before public customer launch; tighter target after paid production |
| RTO | 4 hours for initial production recovery |
| Backup validation | Monthly restore drill, plus before first customer onboarding |
| Credential recovery | 1 hour for critical service secret rotation |

Tighter targets require provider plan confirmation, backup restore testing, and monitoring integration.

### Database Recovery Testing Procedure

Before customer launch:

1. Create a synthetic production-like dataset in a non-production recovery database.
2. Run backup or snapshot.
3. Restore to a separate recovery target.
4. Run migrations/drift checks.
5. Run auth/RBAC/tenant isolation tests.
6. Run security event query and analytics checks.
7. Run alert rule and incident checks.
8. Document actual restore time and observed data loss.

### Credential Recovery Process

For lost or compromised credentials:

1. Identify affected secret scope.
2. Generate replacement secret in the owning provider/vault.
3. Update runtime environment without printing values.
4. Redeploy or restart only affected services.
5. Revoke old credential.
6. Validate service health.
7. Record rotation in secret inventory.
8. Create incident if exposure is suspected.

## 3. WAF and Edge Security Plan

Cloudflare should start conservative. A security SaaS cannot afford edge rules that silently block legitimate customer traffic without a review path.

### Baseline Cloudflare Rules

| Control | Initial mode |
| --- | --- |
| SSL/TLS | Full (strict) |
| Always Use HTTPS | Enabled after origin cert validation |
| HSTS | Disabled during first production validation; enable later with short max-age |
| WAF managed rules | Log/simulate first, then block high-confidence categories |
| Bot protections | Monitor/challenge only on console login and suspicious paths initially |
| Rate limiting | Apply narrow limits to auth, ingest, admin proxy, and enrollment |
| IP reputation | Log/challenge first; block only severe known sources after review |

### Rate Limiting Strategy

| Path | Initial policy |
| --- | --- |
| `/api/auth/login` | strict per IP/email tuple; challenge or temporary block after repeated failures |
| `/api/firewalls/enroll` | strict per IP and token failure; disabled except during controlled enrollment windows |
| `/api/ingest/security-events` | higher service quota, alert on auth failures and abnormal volume |
| `/api/admin/*` | strict per session/user/IP; requires app auth/RBAC and admin token downstream |
| `gateway.uzyntra.com/*` | conservative per source/customer policy; avoid breaking protected customer APIs |

### API Abuse Controls

- Require service token and API key where designed.
- Alert on repeated `401`/`403` for ingest.
- Alert on cross-tenant firewall ownership failures.
- Keep request body size limits.
- Keep webhook SSRF protections.
- Use Cloudflare rules for obvious volumetric abuse, not as a replacement for app-layer auth.

### False-Positive Handling Process

1. Record affected hostname, path, ray ID/request ID, customer/org, timestamp, source IP, and rule ID.
2. Confirm whether the app would have accepted the request without WAF intervention.
3. Temporarily switch the rule to log/challenge for the affected path if business impact is high.
4. Narrow the rule by hostname/path/header/method instead of disabling globally.
5. Add regression test or runbook note if the false positive is likely to recur.
6. Review rule change after 24-48 hours.

## 4. Incident Response Runbook

### Severity Levels

| Severity | Examples | Response target |
| --- | --- | --- |
| SEV1 | database compromise, production-wide outage, exposed admin API, active tenant compromise | immediate response |
| SEV2 | partial outage, telemetry ingestion outage, API key leakage, WAF blocking many legitimate requests | response within 30 minutes |
| SEV3 | isolated customer issue, alert delivery degradation, monitoring gap | same business day |
| SEV4 | documentation, minor operational follow-up | planned work |

### Security Incident Detection

Signals:

- unusual audit events.
- repeated auth failures.
- abnormal API key usage.
- cross-tenant access denial spikes.
- high/critical detector spikes.
- unexpected admin route usage.
- secrets appearing in logs or tickets.

Procedure:

1. Triage signal and assign severity.
2. Preserve logs and audit records.
3. Identify affected tenant, service, credential, and timeframe.
4. Contain by disabling keys, sessions, enrollment, or affected integrations.
5. Rotate secrets if exposure is plausible.
6. Validate tenant isolation after containment.
7. Communicate internally, then externally if customer impact is confirmed.
8. Document timeline, root cause, and corrective actions.

### Tenant Compromise

1. Disable affected user sessions.
2. Rotate affected tenant API keys.
3. Review audit events and security events for scope.
4. Check service accounts and notification integrations.
5. Lock risky administrative actions if needed.
6. Coordinate customer notification.
7. Restore access only after owner verification.

### API Key Leakage

1. Revoke leaked key.
2. Create replacement key through normal control-plane path.
3. Search logs/audit events for key prefix usage.
4. Confirm no plaintext key is present in logs or database.
5. Audit affected service account permissions.
6. Notify tenant if customer-owned key.

### Database Compromise

1. Freeze relevant credentials.
2. Rotate `DATABASE_URL`, auth secrets, API key secret, session secret, management token secret, and integration encryption key according to exposure scope.
3. Revoke database users or passwords.
4. Restore from clean backup if integrity is uncertain.
5. Re-issue sessions/API keys if required.
6. Preserve forensic artifacts.
7. Execute notification obligations.

### Service Outage

1. Check Vercel, Railway, Supabase, Cloudflare status.
2. Check recent deploys, env changes, DNS changes, and WAF changes.
3. Roll back latest deployment if correlated.
4. Disable or relax edge rule if WAF-related.
5. Keep generated provider URLs available for internal diagnostics.
6. Update status page once public.

### Rollback

Control plane rollback:

- Revert Vercel deployment.
- Keep database intact unless migration rollback is explicitly validated.
- Roll back DNS only if custom-domain routing is the failure.

Gateway rollback:

- Revert Railway deployment.
- Confirm `/healthz` and `/readyz`.
- Confirm admin port remains private.
- Disable telemetry temporarily if it causes error loops.

WAF/DNS rollback:

- Switch problematic records to DNS-only if proxy causes errors.
- Disable or narrow the offending rule.
- Revalidate TLS and app health.

## 5. Secret Management Review

### Storage

| Secret class | Storage |
| --- | --- |
| Vercel runtime secrets | Vercel Production environment variables and organization vault inventory |
| Railway runtime secrets | Railway production service variables and organization vault inventory |
| Supabase database credentials | Supabase project settings and organization vault inventory |
| Emergency break-glass credentials | Restricted organization vault with MFA |
| Future AWS secrets | AWS Secrets Manager or equivalent |

### Rotation Frequency

| Secret | Rotation cadence |
| --- | --- |
| one-time enrollment token | immediately after enrollment, then removed |
| API keys/service account keys | 90 days or incident-triggered |
| `FIREWALL_ADMIN_TOKEN` | 90 days or incident-triggered |
| `CONTROL_PLANE_SERVICE_TOKEN` | 90 days or incident-triggered |
| auth/session/API-key secrets | 180 days or incident-triggered; plan user/session impact |
| database password | 180 days or incident-triggered |
| integration encryption key | incident-triggered only unless key rewrap tooling exists |

### Emergency Rotation Procedure

1. Identify blast radius and dependent services.
2. Generate replacement secret in vault.
3. Update provider environment variable.
4. Redeploy or restart affected service.
5. Validate health and auth behavior.
6. Revoke old secret.
7. Search logs for accidental exposure.
8. Record rotation time, owner, and validation result.

### Separation Requirements

- Production secrets must be generated fresh.
- Staging secrets must not be copied into Production.
- Production secrets must not be set on Preview deployments.
- Meet secrets remain fully separate.
- No secrets in `.env.example`, docs, screenshots, terminal output, logs, or git.

## 6. Production Security Checklist

| Area | Required validation |
| --- | --- |
| TLS | valid certs, Full (strict), HTTP redirect, TLS 1.2+ |
| Headers | security headers reviewed for console and API responses |
| CORS | restricted to expected origins; no wildcard credentials |
| Authentication | login failure behavior, session cookie security, logout |
| RBAC | owner/admin/viewer boundaries, BFF permissions, firewall-scoped permissions |
| Audit logging | auth, RBAC, API keys, enrollment, ingestion, alerts, incidents, admin proxy |
| Tenant isolation | org A cannot access org B users, firewalls, events, alerts, incidents |
| Firewall isolation | firewall A cannot submit/query firewall B events |
| Dependency scanning | `npm audit` or equivalent, Rust dependency audit, GitHub Dependabot/security alerts |
| Secret scanning | git history and working tree scan before release |
| Admin exposure | public `:9090` unreachable |
| Database | backups, restore test, access control, migration drift check |
| Webhooks | SSRF validation, HTTPS-only targets, signature validation |
| Alerting | operational alerts route to humans; security alerts do not create unbounded noise |

## 7. Launch Risk Assessment

| Risk | Mitigation | Owner | Priority |
| --- | --- | --- | --- |
| Production database restore fails or is too slow | Complete restore drill before launch; record actual RTO/RPO | Platform owner | P0 |
| Production secrets reused from staging | Generate fresh production secrets; audit Vercel/Railway/Supabase scopes | Security owner | P0 |
| Admin port exposed | Port scan production gateway before DNS; keep `:9090` private | Backend owner | P0 |
| WAF blocks legitimate traffic | Start rules in log/challenge mode; narrow by path; define false-positive process | Edge/security owner | P1 |
| Monitoring misses outage | Configure external uptime checks and provider alerts before launch | Operations owner | P0 |
| Alert fatigue hides real incident | Start with high-signal alerts and severity routing; review after first week | Security owner | P1 |
| Telemetry ingestion outage unnoticed | Alert on missing gateway telemetry and ingest failures | Platform owner | P0 |
| Tenant isolation regression | Run release-gate isolation tests before launch and after any auth/RBAC change | UI/control-plane owner | P0 |
| API key leakage | Key prefix audit, revocation procedure, no plaintext key logs | Security owner | P0 |
| Production DNS points to staging | Explicit DNS review before `console`/`gateway` records; two-person approval | DNS owner | P0 |
| Cloudflare proxy causes origin/TLS issue | Validate DNS-only first; enable proxy after smoke tests | Edge/security owner | P1 |
| Incident roles unclear | Assign incident commander, comms owner, recovery owner before launch | Operations owner | P0 |
| Dependency vulnerability lands near launch | Run dependency scan before release; block critical/high exploitable issues | Engineering owner | P1 |

## Phase 7.11 Validation Checklist

Before moving to Phase 8, confirm:

1. Monitoring owner and tooling selected.
2. Backup restore drill scheduled or completed.
3. RPO/RTO accepted.
4. WAF baseline policy approved.
5. Incident response roles assigned.
6. Secret inventory template ready.
7. Emergency rotation procedure accepted.
8. Production security checklist accepted.
9. Launch risk table reviewed with owners.
10. Decision made: Phase 8 production launch or further enterprise hardening.

## Phase 7.11 Status

PHASE 7.11 STATUS: READY

This phase is ready as an operational hardening plan. No production deployment was performed, no production DNS was created, no production secrets were created, no production data was migrated, no commits/releases were made, and Phase 8 was not started.

Recommended next decision:

- Phase 8 Production Launch if operational owners, backup drill, monitoring, WAF baseline, and incident response are accepted.
- Further enterprise hardening if compliance controls, advanced monitoring, or SOC workflows must be in place before public launch.

