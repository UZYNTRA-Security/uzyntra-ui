# Phase 8.12 - Production Readiness Gaps

Status: READY

This gap list is a pre-production hardening register for the reconstructed Phase 8 platform baseline. It does not implement production changes.

## Critical

None currently blocking the Phase 8 platform baseline freeze.

## High

### Database-Level Tenant Ownership Constraints

Current state:

- Application/API/RBAC tenant isolation tests pass.
- Direct SQL can still create selected cross-tenant reference mismatches, such as `security_events.organization_id` paired with a firewall owned by another organization.

Risk:

- Privileged database misuse or a compromised write path could create inconsistent tenant-scoped data.

Recommendation:

- Add selective composite foreign keys for high-risk tenant-scoped relationships before production customer traffic.
- Start with `security_events`, then extend to detection, alert, incident, policy decision, enforcement, SOAR, and evidence tables.

### Production Secret Separation

Current state:

- Staging/validation secrets are not suitable for production.

Risk:

- Secret reuse would expand blast radius between staging and production.

Recommendation:

- Generate fresh production-only secrets for database, sessions, API keys, management tokens, service tokens, webhook signing, integration encryption, and firewall admin credentials.

### Backup and Restore Proof

Current state:

- Migration reproducibility is validated.
- Full production backup/restore rehearsal is not yet validated.

Risk:

- Recovery time and recovery point assumptions are unproven.

Recommendation:

- Run a Supabase backup restore rehearsal before production launch.
- Define RPO/RTO and document operator steps.

## Medium

### Runtime Observability Thresholds

Current state:

- Observability planning exists.
- Production alert thresholds are not tuned with live traffic.

Risk:

- Alert noise or missed operational degradation.

Recommendation:

- Establish baseline dashboards for Vercel, Railway/gateway, Supabase, ingestion failures, notification failures, and security event volume.

### WAF and Rate Limit Tuning

Current state:

- DNS/TLS staging validation passed.
- Production Cloudflare WAF/rate-limit policy remains a controlled future step.

Risk:

- Overly aggressive edge rules may block legitimate customers; weak rules may leave abuse paths open.

Recommendation:

- Start in log/simulate mode where possible.
- Promote rules gradually after smoke testing.

### Module Type Warnings

Current state:

- Node reports `MODULE_TYPELESS_PACKAGE_JSON` warnings in tests.

Risk:

- Small performance overhead and noisy CI logs.

Recommendation:

- Evaluate adding `"type": "module"` in a separate maintenance branch because it may affect module loading semantics.

### Database Trust Boundary Documentation

Current state:

- Application layer owns tenant authorization.
- Database direct-write trust model is implicit.

Risk:

- Operators may overestimate database-enforced tenant isolation.

Recommendation:

- Document that direct database write access is privileged/trusted until composite ownership constraints are added.

## Low

### Historical Migration Shape

Current state:

- Phase 8 baseline migration chain is reproducible from zero.
- Phase 8.4 through 8.10 are consolidated into `0014_magenta_kate_bishop` on the reconstructed branch.

Risk:

- Historical phase granularity is less visible in migration filenames.

Recommendation:

- Keep phase documentation as the source of phase-by-phase narrative.
- Do not split the regenerated migration unless a future release process requires it.

### Placeholder Documentation Values

Current state:

- Documentation and examples contain placeholder secret names and local sample URLs.

Risk:

- Low, as no real secrets were found.

Recommendation:

- Review docs before public publication and keep examples clearly placeholder-based.

## Recommended Order Before Production

1. Freeze Phase 8 baseline.
2. Create Phase 9 branch from the frozen baseline.
3. Reapply/resume Phase 9 identity cleanly.
4. Add database-level tenant ownership hardening before production traffic.
5. Create production Supabase project and validate backup/restore.
6. Generate fresh production secrets.
7. Deploy production console and gateway.
8. Add production DNS/TLS.
9. Run production smoke and rollback drills.
