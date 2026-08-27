# Phase 7.8 - Enterprise Domain Architecture and DNS/TLS Planning

Status: planning complete. Do not create DNS records, deploy production, expose customer traffic, migrate production secrets, or start Phase 8 in this phase.

Phase 7.7 staging release gate is READY. Phase 7.8 defines the domain and TLS architecture to use next in Phase 7.9 staging custom-domain validation.

## Current Validated Staging State

| Component | Current state |
| --- | --- |
| Control plane | Vercel Preview for `uzyntra-ui`, staging branch |
| Gateway | Railway staging service |
| Database | Supabase `uzyntra-firewall-validation`, ref `oulgbbizglfacgnwnpjk`, used as staging under the current free-plan constraint |
| Trust boundary | Vercel protection bypass plus `x-uzyntra-service-token` |
| Runtime paths | Authentication, RBAC, enrollment, telemetry, tenant isolation, and security event ingestion validated |

Staging is operational on generated provider URLs. Custom DNS should be introduced first for staging hostnames, then production hostnames only after staging custom-domain validation passes.

## Final Domain Map

| Hostname | Environment | Purpose | Initial hosting | Decision |
| --- | --- | --- | --- | --- |
| `uzyntra.com` | Production | Corporate/product site | Vercel or existing site host | Keep separate from Security SaaS app routing |
| `meet.uzyntra.com` | Production | UZYNTRA Meet | Vercel + Supabase + LiveKit | Keep completely separate |
| `staging-console.uzyntra.com` | Staging | Internal staging control plane | Vercel Preview/staging | Create first in Phase 7.9 |
| `staging-gateway.uzyntra.com` | Staging | Internal staging Rust firewall gateway | Railway staging | Create first in Phase 7.9 |
| `console.uzyntra.com` | Production | Customer/admin control plane | Vercel Production | Reserve for production cutover |
| `gateway.uzyntra.com` | Production | Rust firewall data plane | Railway initially, AWS later if needed | Reserve for production cutover |
| `api.uzyntra.com` | Future production | Public API and integrations | TBD API layer | Reserve, do not point at control plane yet |
| `docs.uzyntra.com` | Future production | Documentation/API references | Docs provider, Vercel, or static docs host | Reserve until docs host is selected |
| `status.uzyntra.com` | Future production | Public status page | Status provider | Reserve until status provider is selected |
| `auth.uzyntra.com` | Future production | Dedicated identity service/IdP | TBD | Reserve only |

Do not create these public hostnames:

| Hostname | Reason |
| --- | --- |
| `backend.uzyntra.com` | Exposes implementation detail instead of product role |
| `frontend.uzyntra.com` | Exposes implementation detail instead of product role |
| `database.uzyntra.com` | Suggests direct database exposure |
| `postgres.uzyntra.com` | Suggests direct database exposure |
| `admin.uzyntra.com` | Too broad and likely to attract administrative attack traffic |

## Cloudflare DNS Design

Records below are planned only. Create no records until the owning provider has the exact target and verification requirements.

| Name | Type | Target | Proxy mode | TLS mode | Purpose |
| --- | --- | --- | --- | --- | --- |
| `staging-console` | CNAME | Vercel-provided CNAME target from domain inspection | DNS-only during verification, optionally proxied after validation | Full (strict) after Vercel cert is valid | Staging control plane custom domain |
| `staging-gateway` | CNAME | Railway-provided CNAME target plus required TXT verification | DNS-only during Railway verification, optionally proxied after validation | Full (strict) after Railway cert is issued | Staging gateway custom domain |
| `console` | CNAME | Vercel-provided CNAME target from production domain inspection | DNS-only during verification, optionally proxied after validation | Full (strict) after Vercel cert is valid | Production control plane |
| `gateway` | CNAME | Railway-provided CNAME target plus required TXT verification | DNS-only during Railway verification, proxied only after gateway smoke tests | Full (strict) after Railway cert is issued | Production gateway |
| `api` | CNAME | TBD public API provider target | Do not create yet | Full (strict) when origin exists | Future public API |
| `docs` | CNAME | TBD docs provider target | Provider-dependent | Full (strict) when origin exists | Documentation |
| `status` | CNAME | TBD status provider target | Provider-dependent | Full (strict) when origin exists | Status page |
| `auth` | None | Reserved | None | None | Future identity service |

DNS rules:

- Use Cloudflare as authoritative DNS only after nameserver ownership is confirmed.
- Add provider verification records exactly as Vercel or Railway reports them.
- Keep TXT verification records DNS-only. TXT records are never proxied.
- Prefer DNS-only for initial custom-domain verification to avoid provider validation ambiguity.
- Enable Cloudflare proxy only after origin TLS is valid and smoke tests pass.
- Keep generated provider URLs available as rollback paths.
- Use low TTLs before cutover where Cloudflare allows explicit TTL control. Proxied records use Cloudflare automatic TTL behavior.

## TLS Configuration

Recommended Cloudflare SSL/TLS mode: Full (strict).

Minimum requirements:

- TLS 1.2 minimum.
- TLS 1.3 enabled where provider support is available.
- Valid, unexpired origin certificate matching the hostname before enabling Full (strict).
- HTTPS redirect enabled after the origin cert is valid.
- HSTS only after staging and production domains are stable.

HSTS rollout:

| Stage | Setting |
| --- | --- |
| Initial validation | HSTS disabled |
| Post-validation staging | Optional short max-age, no preload |
| Production warm-up | Short max-age, no preload |
| Production stable | Longer max-age |
| Final hardening | Consider `includeSubDomains` and preload only after all subdomains are permanently HTTPS-safe |

Certificate strategy:

| Hostname | Certificate approach |
| --- | --- |
| `staging-console.uzyntra.com` | Vercel managed TLS |
| `console.uzyntra.com` | Vercel managed TLS |
| `staging-gateway.uzyntra.com` | Railway managed TLS initially |
| `gateway.uzyntra.com` | Railway managed TLS initially; Cloudflare Origin CA only if Cloudflare remains the mandatory edge path |
| `docs.uzyntra.com` | Provider managed TLS |
| `status.uzyntra.com` | Provider managed TLS |

## Gateway Security Review Before Exposure

Before any gateway custom domain receives traffic, verify:

- Public gateway listens only on the intended public HTTP port exposed by Railway.
- Admin listener remains bound to `127.0.0.1:9090` or another non-public private interface.
- Raw `:9090` is not reachable from the internet.
- `FIREWALL_ADMIN_TOKEN` remains required for admin operations.
- Control-plane machine requests require both Vercel bypass and service token where Vercel protection is active.
- Gateway request authentication and rate limits are enabled.
- Telemetry privacy controls sanitize metadata before delivery.
- Logs do not contain service tokens, API keys, enrollment tokens, bypass secrets, database URLs, cookies, or authorization headers.
- Health and readiness endpoints expose no sensitive runtime configuration.

## Vercel Configuration Plan

Production domain:

- `console.uzyntra.com`

Staging domain:

- `staging-console.uzyntra.com`

Environment separation:

| Vercel environment | Domain | Secrets |
| --- | --- | --- |
| Preview/staging | `staging-console.uzyntra.com` and generated preview URLs | Staging-only secrets |
| Production | `console.uzyntra.com` | Production-only secrets |

Requirements:

- Do not reuse staging secrets in Production.
- Do not reuse production secrets in Preview.
- Replace the current Preview-global staging workaround with a dedicated staging Vercel project or custom environment before production traffic exists, if feasible.
- Keep Deployment Protection enabled for Preview/staging.
- For machine access to protected Preview deployments, use Vercel protection bypass plus `x-uzyntra-service-token`.

## Railway Domain Plan

Current staging:

- Service: `uzyntra-api-firewall-staging`
- Generated URL: `https://uzyntra-api-firewall-staging-staging.up.railway.app`

Future staging:

- `staging-gateway.uzyntra.com`

Future production:

- `gateway.uzyntra.com`

Migration steps:

1. Add the custom domain to the Railway staging service.
2. Capture the exact CNAME and TXT verification records from Railway.
3. Add the Cloudflare CNAME and TXT records for `staging-gateway`.
4. Wait for Railway domain verification and certificate issuance.
5. Run `/healthz` and `/readyz` over HTTPS.
6. Run one controlled gateway request through the custom domain.
7. Confirm control-plane telemetry still succeeds.
8. Repeat the same process for production only after staging custom-domain validation is READY.

## Security Risks

| Risk | Mitigation |
| --- | --- |
| Preview-global staging secrets leak into unintended preview deployments | Prefer dedicated staging Vercel project or custom environment; audit Preview deployments before DNS |
| Cloudflare proxy breaks provider verification | Use DNS-only until Vercel/Railway verification and TLS issuance are complete |
| Gateway public domain accidentally exposes admin API | Verify admin bind address and network exposure before CNAME creation |
| HSTS locks an unstable hostname into HTTPS | Delay HSTS until domain and cert behavior is stable |
| Production hostname points to staging | Create staging records first; require explicit production checklist before `console` or `gateway` records |
| Provider generated URL remains publicly reachable | Treat generated URLs as valid origins; keep auth/rate limits active regardless of custom domain |
| Origin IP or platform target exposure | Use Cloudflare proxy only after origin validation; consider origin rotation if a stable IP is ever exposed |

## Implementation Checklist

Phase 7.9 should validate staging custom domains only:

1. Confirm Cloudflare zone ownership and MFA.
2. Confirm Vercel and Railway current staging targets.
3. Add `staging-console.uzyntra.com` to Vercel only.
4. Add Vercel-required DNS records in Cloudflare.
5. Validate Vercel certificate and deployment protection behavior.
6. Add `staging-gateway.uzyntra.com` to Railway only.
7. Add Railway-required CNAME and TXT records in Cloudflare.
8. Validate Railway certificate and target port.
9. Run control-plane browser/auth smoke tests on `staging-console`.
10. Run gateway `/healthz` and `/readyz` checks on `staging-gateway`.
11. Run machine-auth, enrollment-disabled, and telemetry smoke tests through staging domains.
12. Confirm no production records, production secrets, or production deployments changed.

Production domain work should wait until Phase 8 production infrastructure preparation or a later explicit production DNS phase.

## Rollback Plan

For staging:

1. Remove or disable the Cloudflare `staging-console` or `staging-gateway` CNAME.
2. Remove the matching custom domain from Vercel or Railway if provider routing is unhealthy.
3. Use generated provider URLs for continued staging validation.
4. Re-run health, auth, and telemetry checks on generated URLs.
5. Keep provider verification records only if they are harmless and needed for retry; otherwise remove them.

For production later:

1. Lower TTLs before production cutover where possible.
2. Keep previous provider route available until smoke tests pass.
3. If cutover fails, remove or repoint the affected Cloudflare record.
4. Disable Cloudflare proxy if proxy behavior causes errors and direct provider TLS is healthy.
5. Roll back provider domain binding if the origin receives incorrect traffic.
6. Do not roll back database migrations through DNS rollback.

## Phase 7.8 Status

PHASE 7.8 STATUS: READY

This phase is ready because the enterprise domain map, DNS record plan, TLS posture, gateway exposure requirements, implementation order, and rollback plan are documented. No DNS records were created, no production resources were modified, no production deployment occurred, and Phase 8 was not started.

Recommended next phase:

Phase 7.9 - Staging Custom Domain Validation.

