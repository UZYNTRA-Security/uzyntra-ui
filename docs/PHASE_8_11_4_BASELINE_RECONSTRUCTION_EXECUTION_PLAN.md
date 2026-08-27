# Phase 8.11.4 Baseline Reconstruction Execution Plan

Status: READY for controlled reconstruction approval.

Phase 8 release baseline status: NOT READY.

Date: 2026-08-27

Repository: `api_firewall_ui_phase6`

Observed starting commit: `8884e4786d5c5b9d6ba3ac5884058546e1532986`

Observed starting tag: `phase-6-alerts-integrations`

## Scope

This phase prepares the Phase 8 baseline reconstruction plan only.

No reconstruction was executed.

No branches were created.

No files were moved.

No migrations were modified.

No commits, pushes, tags, releases, deployments, DNS changes, production secrets, OAuth, SSO, MFA, SAML, or OIDC work were performed.

## Objective

Create a clean Phase 8 release baseline from:

- Phase 6 stable commit
- Phase 7 operational/staging/domain planning
- Phase 8.1 through Phase 8.10 platform implementation
- Phase 8.11 migration integrity repair

Exclude:

- Phase 9.1 identity foundation
- OAuth login
- Google login
- GitHub login
- MFA
- SAML
- OIDC
- SSO

## 1. Source Baseline Analysis

### Stable Starting Point

Use the Phase 6 release commit as the reconstruction base:

- Commit: `8884e4786d5c5b9d6ba3ac5884058546e1532986`
- Tag: `phase-6-alerts-integrations`

This commit represents the last clean released UI baseline before Phase 7, Phase 8, and Phase 9.1 became mixed in the current dirty tree.

### Required Phase 7 Additions

Include Phase 7 operational planning and staging/domain readiness artifacts:

- `docs/PHASE_7_1_ENVIRONMENT_ARCHITECTURE.md`
- `docs/PHASE_7_2_STAGING_ENVIRONMENT_FOUNDATION.md`
- `docs/PHASE_7_8_DOMAIN_DNS_TLS_PLAN.md`
- `docs/PHASE_7_10_PRODUCTION_READINESS_PLAN.md`
- `docs/PHASE_7_11_PRODUCTION_HARDENING_PLAN.md`
- staging machine-auth, enrollment, and telemetry hardening code that is required by the validated control-plane/gateway trust path

### Required Phase 8 Additions

Include Phase 8.1 through Phase 8.10:

| Phase | Capability |
| --- | --- |
| 8.1 | Security operations dashboard and notification delivery observability |
| 8.2 | Advanced detection intelligence |
| 8.3 | Threat intelligence foundation |
| 8.4 | Zero Trust API security planning and foundation |
| 8.5 | Adaptive API protection |
| 8.6 | Policy simulation and decision intelligence |
| 8.7 | SOAR foundation |
| 8.8 | AI security analyst copilot foundation |
| 8.9 | Enterprise SaaS/MSSP security operations |
| 8.10 | Global enterprise scale and ecosystem foundation |
| 8.11 | Platform release baseline, migration integrity reports, metadata repair |

Core Phase 8 directories to include:

- `src/lib/security-operations/`
- `src/lib/advanced-detection/`
- `src/lib/threat-intelligence/`
- `src/lib/zero-trust/`
- `src/lib/adaptive-protection/`
- `src/lib/policy-simulation/`
- `src/lib/soar/`
- `src/lib/ai-copilot/`
- `src/lib/enterprise/`
- `src/lib/global-scale/`
- `src/lib/management/enrollment-contract.js`
- `src/lib/service-auth.js`

Phase 8 UI/API areas to include:

- security operations routes
- detection routes
- threat intelligence routes
- Zero Trust routes
- adaptive protection routes
- policy simulation routes
- SOAR routes
- AI analyst routes
- enterprise/MSSP routes
- global scale/platform routes

Phase 8 tests to include:

- `scripts/test-security-operations.mjs`
- `scripts/test-phase8-advanced-detection.mjs`
- `scripts/test-phase83-threat-intelligence.mjs`
- `scripts/test-zero-trust.mjs`
- `scripts/test-adaptive-protection.mjs`
- `scripts/test-policy-simulation.mjs`
- `scripts/test-soar.mjs`
- `scripts/test-ai-copilot.mjs`
- `scripts/test-enterprise.mjs`
- `scripts/test-global-scale.mjs`
- platform release test script wiring

### Explicitly Excluded Phase 9.1 Additions

Exclude these from the Phase 8 baseline:

- `docs/PHASE_9_IDENTITY_SSO_ENTERPRISE_AUTHENTICATION_PLAN.md`
- `scripts/test-phase9-identity.mjs`
- `src/lib/identity/`
- `package.json` script `test:identity`
- `src/db/schema.js` identity exports/check helpers:
  - `identityProviders`
  - `externalIdentities`
  - `verifiedEmailIdentities`
  - `identityAuditEvents`
- `drizzle/0014_daffy_ultimates.sql`
- `drizzle/meta/0014_snapshot.json`

## 2. Migration Reconstruction Plan

### Current Mixed Sequence

Current uncommitted sequence:

| Migration | Meaning |
| --- | --- |
| `0011_alerts_integrations.sql` | Phase 6 |
| `0012_funny_sentinels.sql` | Phase 8.2 advanced detection |
| `0013_exotic_puck.sql` | Phase 8.3 threat intelligence |
| `0014_daffy_ultimates.sql` | Phase 9.1 identity foundation |
| `0015_safe_mentor.sql` | Phase 8.4 Zero Trust |
| `0016_busy_ultimates.sql` | Phase 8.5 adaptive protection |
| `0017_faithful_blackheart.sql` | Phase 8.6 policy simulation |
| `0018_numerous_richard_fisk.sql` | Phase 8.7 SOAR |
| `0019_breezy_the_enforcers.sql` | Phase 8.7 SOAR adjustment |
| `0020_natural_sinister_six.sql` | Phase 8.7 SOAR adjustment |
| `0021_stiff_robbie_robertson.sql` | Phase 8.8 AI analyst |
| `0022_narrow_storm.sql` | Phase 8.9 enterprise/MSSP |
| `0023_strange_agent_zero.sql` | Phase 8.10 global scale |

### Target Phase 8 Sequence

Target clean Phase 8 baseline:

| Target migration | Meaning |
| --- | --- |
| `0011_alerts_integrations.sql` | Phase 6, with repaired `0011_snapshot.json.prevId` |
| `0012_*` | Phase 8.2 advanced detection |
| `0013_*` | Phase 8.3 threat intelligence |
| `0014_*` | Phase 8.4 Zero Trust, replacing the current identity migration position |
| `0015_*` | Phase 8.5 adaptive protection |
| `0016_*` | Phase 8.6 policy simulation |
| `0017_*` | Phase 8.7 SOAR |
| `0018_*` | Phase 8.7 SOAR adjustment |
| `0019_*` | Phase 8.7 SOAR adjustment |
| `0020_*` | Phase 8.8 AI analyst |
| `0021_*` | Phase 8.9 enterprise/MSSP |
| `0022_*` | Phase 8.10 global scale |

The exact generated names may change if Drizzle regenerates migrations. The release baseline should care about deterministic schema and journal order, not preserving temporary generated names from the mixed dirty tree.

### Which Migrations Need Regeneration

Safe to preserve:

- `0012_funny_sentinels.sql`
- `0013_exotic_puck.sql`

Why:

These are before the identity migration and do not inherit identity schema.

Must be regenerated or replayed in a clean branch:

- current `0015_safe_mentor.sql`
- current `0016_busy_ultimates.sql`
- current `0017_faithful_blackheart.sql`
- current `0018_numerous_richard_fisk.sql`
- current `0019_breezy_the_enforcers.sql`
- current `0020_natural_sinister_six.sql`
- current `0021_stiff_robbie_robertson.sql`
- current `0022_narrow_storm.sql`
- current `0023_strange_agent_zero.sql`

Reason:

Their SQL does not reference Phase 9 identity tables, but their snapshots were generated after `0014_daffy_ultimates.sql`, so snapshots `0015` through `0023` include identity tables. A clean Phase 8 baseline must regenerate these snapshots from a schema that excludes identity.

Must be excluded:

- `0014_daffy_ultimates.sql`
- `0014_snapshot.json`

### Snapshot Regeneration Rules

Do not manually edit large snapshots except for the already-proven `0011_snapshot.json.prevId` repair.

For the clean Phase 8 branch:

1. Remove Phase 9 identity schema from `src/db/schema.js`.
2. Remove the current uncommitted migrations/snapshots from `0014` onward.
3. Recreate Phase 8.4 through Phase 8.10 migrations by applying Phase 8 schema changes in order and running Drizzle generation at each boundary, or by constructing SQL replay files and letting Drizzle produce matching snapshots from clean schema states.
4. Verify each generated snapshot has a `prevId` matching the previous snapshot id.
5. Confirm no snapshot after the reconstructed `0014` contains:
   - `identity_providers`
   - `external_identities`
   - `verified_email_identities`
   - `identity_audit_events`

### Drizzle Journal Rebuild

In the clean Phase 8 branch:

- `drizzle/meta/_journal.json` must be rebuilt to include the clean Phase 8 migration sequence.
- Journal indexes must be contiguous.
- Journal tags must match actual SQL file names.
- Journal timestamps should be monotonic.
- No duplicate tags or indexes.

Do not manually invent journal entries if Drizzle can generate them. If manual journal repair becomes necessary, validate against a true-zero disposable database before committing.

## 3. Branch Strategy

### Branch A - Phase 8 Baseline

Name:

- `phase-8-platform-baseline`

Contains:

- Phase 7 documentation and validated staging/control-plane hardening.
- Phase 8.1 through Phase 8.10 implementation.
- Phase 8.11 release engineering documentation and migration metadata repair.
- Clean Phase 8 migrations and snapshots.

Excludes:

- Phase 9.1 identity foundation.
- OAuth/MFA/SSO files, tests, docs, schema, and migration.

### Branch B - Phase 9 Identity

Name:

- `phase-9-identity`

Contains:

- Current Phase 9.1 identity foundation.
- Future Google OAuth, GitHub OAuth, MFA, SAML, OIDC, and SSO work.

Base:

- Should eventually sit on top of the clean Phase 8 baseline, not the mixed dirty tree.

### Recommended Branch Execution Order

Do this later, only after approval:

1. Create a safety snapshot branch from the current dirty tree.
2. Preserve the current mixed work there.
3. Create `phase-8-platform-baseline` from `8884e4786d5c5b9d6ba3ac5884058546e1532986`.
4. Apply only Phase 7 and Phase 8 changes.
5. Regenerate/replay clean Phase 8 migrations.
6. Validate.
7. Commit and tag Phase 8.
8. Rebase/reapply Phase 9 identity on top of the Phase 8 tag.

## 4. Reconstruction Execution Steps

Do not run these steps until explicitly approved.

### Step 1 - Preserve Current Mixed Work

Create a safety branch:

```text
phase-9-identity-safety
```

Purpose:

- Preserve all current Phase 7, Phase 8, and Phase 9.1 work before extraction begins.
- Avoid losing uncommitted work.

### Step 2 - Create Clean Baseline Branch

Create:

```text
phase-8-platform-baseline
```

Base:

```text
8884e4786d5c5b9d6ba3ac5884058546e1532986
```

### Step 3 - Apply Phase 7 and Phase 8 Non-Migration Files

Apply all Phase 7 and Phase 8 files from the safety branch, excluding:

- Phase 9 identity doc
- Phase 9 identity test
- `src/lib/identity/`
- identity schema definitions
- `test:identity`

### Step 4 - Rebuild Schema Without Identity

Ensure `src/db/schema.js` contains all Phase 8 schema objects except:

- `identityProviders`
- `externalIdentities`
- `verifiedEmailIdentities`
- `identityAuditEvents`

Then run local generation checks.

### Step 5 - Reconstruct Migrations

Preserve:

- `0012_funny_sentinels.sql`
- `0013_exotic_puck.sql`

Regenerate/replay:

- Phase 8.4 Zero Trust
- Phase 8.5 adaptive protection
- Phase 8.6 policy simulation
- Phase 8.7 SOAR
- Phase 8.8 AI analyst
- Phase 8.9 enterprise/MSSP
- Phase 8.10 global scale

Target:

- no identity migration in Phase 8 branch
- no identity tables in snapshots
- contiguous SQL and journal ordering
- valid snapshot graph

### Step 6 - Fresh Validation

Run against only the disposable Supabase validation/staging project:

- `uzyntra-firewall-validation`
- ref: `oulgbbizglfacgnwnpjk`

Validation:

1. Reset only approved app-owned schemas.
2. Run `npm run db:migrate`.
3. Verify table count.
4. Verify journal rows.
5. Run `npm run db:generate`.
6. Run `npm run test:platform-release`.
7. Run `npm run build`.
8. Run `npm audit --omit=dev`.
9. Run secret/artifact scan.
10. Insert rolled-back synthetic validation data.
11. Verify cleanup residue is zero.

### Step 7 - Commit and Tag

Only after validation passes:

Commit:

```text
feat: establish phase 8 security platform baseline
```

Suggested tag:

```text
phase-8-security-platform
```

Do not tag before the exact commit has passed validation.

### Step 8 - Resume Phase 9

Create or update:

```text
phase-9-identity
```

Base it on:

```text
phase-8-security-platform
```

Then reapply Phase 9.1 identity foundation and continue:

- Phase 9.2 Google OAuth
- Phase 9.3 GitHub OAuth
- Phase 9.4 MFA
- Phase 9.5 Enterprise SSO

## 5. Validation Plan

### Database Validation

Required:

- true-zero migration from clean Phase 8 branch
- upgrade migration from Phase 6/Phase 7 state if applicable
- schema comparison after migration
- Drizzle journal verification
- snapshot graph verification
- no identity tables in Phase 8 database

Expected Phase 8-only database:

- Contains Phase 8 security platform tables.
- Does not contain:
  - `identity_providers`
  - `external_identities`
  - `verified_email_identities`
  - `identity_audit_events`

### Application Validation

Run:

- `npm run db:generate`
- `npm run test:platform-release`
- `npm run build`
- `npm audit --omit=dev`

Targeted checks:

- authz
- audit
- API keys
- firewall enrollment
- security event ingestion/query
- Phase 6 alerts/incidents/integrations
- Phase 8 security operations
- advanced detection
- threat intelligence
- Zero Trust
- adaptive protection
- policy simulation
- SOAR
- AI analyst
- enterprise/MSSP
- global scale

### Security Validation

Confirm:

- tenant isolation
- firewall isolation
- RBAC enforcement
- audit persistence
- service-token authentication
- no plaintext API keys
- no credentials in logs
- no production secrets in repository
- no Phase 9 identity auth surfaces in Phase 8 baseline

## 6. Expected Files Affected During Reconstruction

Expected Phase 8 baseline files:

- `package.json`
- `package-lock.json`
- `.env.example`
- `.gitignore`
- `src/db/schema.js`
- `src/components/Sidebar.js`
- Phase 8 `src/app/` pages
- Phase 8 `src/app/api/` routes
- Phase 8 `src/lib/` modules
- Phase 8 `scripts/test-*.mjs`
- Phase 7 and Phase 8 docs
- `drizzle/meta/_journal.json`
- `drizzle/meta/0011_snapshot.json`
- reconstructed Phase 8 SQL migrations
- reconstructed Phase 8 snapshots

Expected Phase 9-only files:

- `docs/PHASE_9_IDENTITY_SSO_ENTERPRISE_AUTHENTICATION_PLAN.md`
- `scripts/test-phase9-identity.mjs`
- `src/lib/identity/index.js`
- identity schema definitions in `src/db/schema.js`
- `drizzle/0014_daffy_ultimates.sql` as currently generated
- `drizzle/meta/0014_snapshot.json` as currently generated

Expected files requiring careful split:

- `src/db/schema.js`
- `package.json`
- `package-lock.json`
- `drizzle/meta/_journal.json`
- `drizzle/meta/*.json`

## 7. Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Losing uncommitted work | High | Create safety branch before reconstruction. |
| Corrupting migration history | High | Reconstruct in separate branch and validate from zero. |
| Accidentally including Phase 9 identity in Phase 8 | High | Add explicit identity-table absence checks. |
| Snapshot drift after removing identity | High | Regenerate/replay snapshots from clean schema states. |
| Test script accidentally references Phase 9 | Medium | Remove `test:identity` from Phase 8 baseline. |
| Phase 8 code indirectly depends on identity schema | Medium | Run grep and platform tests after removal. |
| Drizzle generated names change | Low | Accept changed names if ordering and schema are valid. |

## 8. Rollback Strategy

If reconstruction fails:

1. Stop immediately.
2. Keep the current safety branch untouched.
3. Do not commit the broken baseline.
4. Return to the safety branch.
5. Compare failed schema against validated mixed tree.
6. Decide whether to:
   - continue reconstruction,
   - accept dormant identity in Phase 8,
   - or defer Phase 8 freeze.

If fresh database validation fails:

1. Capture failing migration name and SQL error.
2. Do not patch the disposable database manually.
3. Fix migration source in the reconstruction branch.
4. Reset disposable database again only with approval.
5. Re-run full validation from zero.

If branch separation becomes too costly:

1. Document Option B explicitly.
2. Freeze current validated tree as Phase 8 plus dormant identity foundation only if the user approves the changed release boundary.
3. Do not pretend it is a pure Phase 8 baseline.

## 9. Status

PHASE 8.11.4 STATUS: READY

Meaning:

- Reconstruction source is identified.
- Phase 8 additions are mapped.
- Phase 9 exclusions are mapped.
- Migration reconstruction requirements are defined.
- Branch strategy is defined.
- Validation plan is defined.
- Risks and rollback strategy are documented.

Phase 8 release baseline remains: NOT READY

Next action:

Approve execution of the safety branch plus clean Phase 8 baseline reconstruction. Do not start Phase 9 implementation until the clean Phase 8 baseline is committed, validated, and tagged.
