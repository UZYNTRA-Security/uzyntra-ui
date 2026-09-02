# Phase 9.9.1 Staging Identity Provider Preparation Report

Status: READY

Branch: phase-9-identity-platform

## Objective

Phase 9.9.1 prepares the staging identity validation foundation for live provider testing. It does not activate Google, GitHub, SAML, OIDC, SCIM, or MFA production credentials. It creates the framework needed to verify staging provider readiness, environment separation, secret handling, and validation evidence before Phase 9.9.2 starts.

## Current Identity Architecture

Implemented identity layers:

- Password authentication remains the baseline login authority.
- Google and GitHub OAuth provider abstractions exist.
- OAuth state, PKCE, expiration, replay, and redirect normalization controls exist.
- MFA/TOTP, recovery codes, and WebAuthn/passkey foundation exist.
- Enterprise SAML and OIDC provider foundations exist.
- SCIM provider, token, user, and group provisioning foundations exist.
- Identity security operations, risk scoring, access reviews, observability, recovery, break-glass, and audit reporting exist.
- `/identity-admin`, `/identity-security`, and `/identity-observability` provide identity operator visibility.

Staging identity validation must now prove these foundations against real external providers without introducing production risk.

## Staging Identity Provider Configuration Framework

Added:

- `src/lib/identity-live-validation/index.js`
- `scripts/test-phase99-live-identity-prep.mjs`
- `npm run test-live-identity-prep`

The framework supports preparation checks for:

- Google OAuth
- GitHub OAuth
- Enterprise SAML
- Enterprise OIDC
- SCIM
- MFA device validation

The framework produces:

- staging callback URLs
- required variable names
- variable status as `set` or `missing`
- required evidence names
- environment-separation findings
- readiness summary

It does not print or return secret values.

## Environment Separation Validation

Expected staging origin:

- `https://staging-console.uzyntra.com`

Production origin reserved:

- `https://console.uzyntra.com`

Validation rules:

- staging validation must not use the production console origin
- production-prefixed environment variables must not appear in staging validation
- Google secret cannot be configured without Google client ID
- GitHub secret cannot be configured without GitHub client ID
- returned readiness summaries must not contain configured secret values

## External Provider Requirements

Google OAuth:

- dedicated Google Cloud OAuth client for staging
- redirect URI: `https://staging-console.uzyntra.com/api/auth/oauth/google/callback`
- consent screen limited to staging test users
- staging-only `GOOGLE_CLIENT_ID`
- staging-only `GOOGLE_CLIENT_SECRET`

GitHub OAuth:

- dedicated GitHub OAuth app for staging
- homepage URL: `https://staging-console.uzyntra.com`
- callback URL: `https://staging-console.uzyntra.com/api/auth/oauth/github/callback`
- staging-only `GITHUB_CLIENT_ID`
- staging-only `GITHUB_CLIENT_SECRET`

Enterprise SAML:

- staging IdP application in Entra, Okta, Auth0, or equivalent
- ACS URL: `https://staging-console.uzyntra.com/api/auth/sso/saml/<provider>/callback`
- SP Entity ID: `https://staging-console.uzyntra.com`
- staging-only metadata/certificate material
- no production SAML certificate reuse

Enterprise OIDC:

- staging OIDC application
- callback URL: `https://staging-console.uzyntra.com/api/auth/sso/oidc/<provider>/callback`
- staging-only issuer/client ID/client secret reference
- staging-only `SSO_ENTERPRISE_OIDC_CLIENT_SECRET`

SCIM:

- staging SCIM provider in UZYNTRA
- staging SCIM client from Okta, Entra, or equivalent
- SCIM base URL: `https://staging-console.uzyntra.com/scim/v2`
- staging-only generated SCIM token
- token value shown once and never stored plaintext

MFA:

- staging test users only
- Google Authenticator
- Microsoft Authenticator or 1Password
- Chrome passkey
- Windows Hello or hardware key if available

## Secret Handling

Rules:

- secrets must enter only through Vercel/Railway/Supabase or provider secret managers
- no secret values in Git
- no secret values in documentation
- no secret values in screenshots
- no secret values in logs
- no staging secret promotion to production
- rotate any staging credential exposed during validation

Tracked variable names only:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `SSO_ENTERPRISE_OIDC_CLIENT_SECRET`
- `AUTH_MFA_SECRET_ENCRYPTION_KEY`
- `AUTH_API_KEY_SECRET`

Non-secret environment boundary placeholders:

- `UZYNTRA_ENVIRONMENT`
- `UZYNTRA_PUBLIC_APP_URL`

## Test Account Matrix

Required staging users:

| Account | Purpose | Provider |
| ------- | ------- | -------- |
| staging-google-owner | Google OAuth success, account linking | Google |
| staging-google-unverified | unverified email rejection | Google |
| staging-github-owner | GitHub OAuth success | GitHub |
| staging-github-no-email | GitHub missing email behavior | GitHub |
| staging-sso-user | SAML/OIDC success | Enterprise IdP |
| staging-scim-user | SCIM create/update/disable/delete | SCIM |
| staging-mfa-user | TOTP/WebAuthn/recovery testing | MFA |
| staging-breakglass-admin | recovery drill only | Recovery |

All identifiers should be masked in reports.

## Security Controls

Preparation controls:

- staging callback URL validation
- production origin detection
- production-prefixed variable detection
- secret value leakage detection
- masked evidence helpers
- provider-specific required variable checks

Existing identity controls to preserve:

- generic login failure responses
- OAuth state and PKCE
- OAuth callback replay defense
- SAML/OIDC assertion and callback validation
- MFA challenge expiry and replay protection
- recovery-code single use
- SCIM hashed tokens
- organization-scoped identity resources
- RBAC-gated identity administration
- audit logging for identity lifecycle events

## Validation Results

Passed:

- `npm run test-live-identity-prep`

Coverage:

- Google/GitHub callback URL generation
- SAML/OIDC/SCIM/MFA readiness checklist shape
- required variable status reporting
- staging/production boundary validation
- production-origin rejection for staging validation
- production-prefixed variable rejection
- masked provider evidence output
- secret leakage failure detection

## Remaining Steps

Next:

- Phase 9.9.2 Google/GitHub OAuth live staging validation

Then:

- Phase 9.9.3 Enterprise SSO validation
- Phase 9.9.4 SCIM validation
- Phase 9.9.5 MFA device validation
- Phase 9.9.6 disaster recovery drill
- Phase 9.9.7 evidence collection and final live validation report

## Restrictions Preserved

No real provider credentials were added.

No:

- production deployment
- production DNS
- production secrets
- real Google/GitHub activation
- real enterprise SSO credentials
- real SCIM tokens
- database reset
- Phase 9.10 freeze work
- Phase 10 work

## Decision

PHASE 9.9.1 STATUS: READY

The staging identity provider preparation framework is ready. Live provider validation should proceed one provider family at a time, starting with Phase 9.9.2 Google/GitHub OAuth staging validation.
