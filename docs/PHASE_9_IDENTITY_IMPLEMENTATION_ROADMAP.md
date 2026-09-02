# Phase 9 - Identity Implementation Roadmap

Status: READY FOR PLANNING BASELINE

Branch: `phase-9-identity-platform`

Source baseline:

- Tag: `phase-8-platform-baseline-v1.0`
- Commit: `ae124226c56bbf28f2f4cdf086905c32c77f88f6`

This branch starts from the frozen Phase 8 platform baseline. It does not include the previous mixed Phase 9 identity safety branch state.

## Baseline Verification

Phase 8 baseline state:

- Migration chain ends at `0014_magenta_kate_bishop`.
- Drizzle journal final entry is `0014_magenta_kate_bishop`.
- Phase 8 platform schema remains present.
- Phase 9 identity implementation files are absent.
- OAuth, MFA, SAML, OIDC, and SCIM implementation is not present yet.

The previous mixed identity work remains preserved separately on `phase-9-identity` at commit `05df0c25e10437a76da830a954255f0859d173d1`.

## Phase 9 Objective

Phase 9 introduces a formal identity platform while preserving the existing password login, session security, RBAC model, tenant isolation, audit logging, service accounts, API keys, and firewall enrollment model.

OAuth and enterprise SSO are additive identity providers. They must not replace the existing authentication path or weaken the established authorization boundary.

## Implementation Sequence

| Phase | Scope | Boundary |
| --- | --- | --- |
| 9.1 | Identity Foundation | Internal identity-provider abstraction, external identity linking, account linking, identity audit model |
| 9.2 | OAuth Integration | Google OAuth/OIDC, GitHub OAuth, callback security, state validation, PKCE |
| 9.3 | Enterprise Authentication | SAML, enterprise OIDC providers, tenant SSO policies |
| 9.4 | MFA | TOTP, WebAuthn/passkeys, recovery codes, step-up authentication |
| 9.5 | Identity Governance | SCIM provisioning, lifecycle management, access reviews |

Each sub-phase must follow:

1. Plan.
2. Implement.
3. Test.
4. Validate release gate.

Do not batch all Phase 9 migrations before implementation. Identity touches authentication, users, sessions, organizations, RBAC, and audit trails, so each boundary must remain reviewable.

## 9.1 Identity Foundation

Planned capabilities:

- Identity provider registry.
- External identity records.
- Account linking workflow.
- Verified identity attributes.
- Identity audit events.
- Provider-neutral identity lookup service.

Security requirements:

- Keep password authentication working.
- Preserve existing session issuance and session revocation behavior.
- Never store OAuth provider tokens in plaintext.
- Hash or encrypt provider identifiers where appropriate.
- Audit account linking, unlinking, provider verification, and identity failures.
- Enforce tenant isolation on every identity-to-organization relationship.

## 9.2 OAuth Integration

Planned providers:

- Google OAuth/OIDC.
- GitHub OAuth.

Required controls:

- State validation.
- PKCE where supported.
- Strict redirect URI allowlists.
- CSRF protection.
- Provider issuer/audience validation.
- Email verification checks.
- Safe account-linking prompts.
- Duplicate identity prevention.

OAuth secrets must live only in environment secret stores. They must not be committed, logged, exposed through client bundles, or reused between staging and production.

## 9.3 Enterprise Authentication

Planned capabilities:

- Tenant-managed SAML configuration.
- Tenant-managed enterprise OIDC configuration.
- SSO enforcement policies.
- Domain-based discovery.
- Just-in-time provisioning rules.
- SSO audit events.

Required controls:

- Tenant-scoped identity provider configuration.
- Metadata validation.
- Certificate rotation path.
- SSO rollback path.
- Emergency owner access path.

## 9.4 MFA

Planned capabilities:

- TOTP enrollment and verification.
- WebAuthn/passkey enrollment and verification.
- Recovery codes.
- MFA reset workflow.
- Step-up authentication for sensitive actions.

Required controls:

- Encrypted MFA secrets.
- Hashed recovery codes.
- Audit all enrollment, challenge, recovery, and reset events.
- Do not enable tenant-wide MFA enforcement until recovery and emergency access flows are validated.

## 9.5 Identity Governance

Planned capabilities:

- SCIM user provisioning.
- User lifecycle management.
- Deprovisioning workflows.
- Access reviews.
- Stale access detection.
- Identity governance audit exports.

Required controls:

- Idempotent provisioning.
- Tenant-scoped SCIM tokens.
- Least-privilege SCIM permissions.
- Full audit trail for create, update, disable, and delete operations.

## RBAC And Audit Requirements

Identity work must use existing RBAC patterns and add permissions only when required.

Recommended future permissions:

- `identity.read`
- `identity.manage`
- `identity.providers.manage`
- `identity.sso.manage`
- `identity.mfa.manage`
- `identity.governance.manage`

Every identity control-plane mutation must emit an audit event with:

- organization ID
- actor ID
- target user or identity ID
- action
- provider type
- result
- request ID
- timestamp

Audit events must not include provider secrets, access tokens, refresh tokens, authorization codes, MFA secrets, recovery codes, or raw assertions.

## Tenant Isolation Requirements

Identity records must never allow cross-tenant linking or lookup leakage.

Required checks:

- External identity belongs to exactly one user account unless an explicit account-linking workflow is active.
- Account linking must require an authenticated local session or a verified provider callback.
- Organization membership must still be resolved through existing membership/RBAC tables.
- SSO provider configuration must be scoped to a tenant.
- SCIM credentials must be scoped to a tenant.

## Secret Handling Requirements

Never commit or print:

- OAuth client secrets
- SAML private keys
- OIDC client secrets
- SCIM tokens
- MFA seed secrets
- recovery codes
- provider refresh tokens

Production identity secrets must be generated separately from staging secrets.

## Release Gate Expectations

Each Phase 9 sub-phase should validate:

- authentication correctness
- session security
- RBAC enforcement
- tenant isolation
- audit persistence
- provider secret safety
- migration reproducibility
- clean build
- no Phase 8 baseline regression

No Phase 9 release should be frozen until a fresh disposable database migration and identity-specific security validation both pass.
