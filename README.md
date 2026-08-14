# 🛡️ UZYNTRA UI — Operator Control Console

<p align="center">
  <img src="public/uzyntra-logo-mark.png" alt="UZYNTRA Logo" width="120"/>
</p>

<p align="center">
  <b>Advanced API Threat Intelligence & Control Platform UI</b>
</p>

<p align="center">
  <a href="https://github.com/UZYNTRA-Security/uzyntra-ui">
    <img src="https://img.shields.io/badge/UI-Next.js-black?style=for-the-badge&logo=next.js" />
  </a>
  <a href="https://github.com/UZYNTRA-Security/uzyntra-api-firewall">
    <img src="https://img.shields.io/badge/Backend-Rust-orange?style=for-the-badge&logo=rust" />
  </a>
  <img src="https://img.shields.io/badge/Status-Production Ready-success?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Security-Focused-blue?style=for-the-badge" />
</p>

---

## 🚀 Overview

**UZYNTRA UI** is a professional operator dashboard built for controlling and monitoring the **UZYNTRA Rust API Firewall**.

It provides a **real-time control plane** for:

- 📊 Monitoring security telemetry
- 🚨 Inspecting attack events
- 🛡️ Managing mitigations
- 🧠 Tracking source reputation
- 📜 Reviewing audit logs
- ⚙️ Controlling security policy

---

## 🚀 Why UZYNTRA?

UZYNTRA is a modern API security platform designed for real-time threat detection, analysis, and response.
Built with performance (Rust), usability (Next.js), and security-first principles, it provides a complete control plane + data plane architecture for protecting APIs at scale.

---

## 🔗 Backend (Required)

This UI connects to the Rust backend:

👉 **UZYNTRA API Firewall (Backend Repo)**  
https://github.com/UZYNTRA-Security/uzyntra-api-firewall

> ⚠️ The backend **must be running** for the UI to function.

---

## ✨ Features

- 📊 **Dashboard**
  - Metrics overview (events, blocks, reputation)
  - Recent activity monitoring

- 🔍 **Events Explorer**
  - Search & filter security events
  - Inspect findings (SQLi, SSRF, etc.)

- 🛡️ **Mitigation Control**
  - Active block management
  - Manual IP blocking with TTL

- 🧠 **Reputation System**
  - Suspicious source scoring
  - Reset reputation entries

- 📜 **Audit Trail**
  - Full operator activity tracking
  - Action history & accountability

- ⚙️ **Policy Management**
  - Global rule modes
  - Route-based overrides
  - Rate limiting controls

---

## 🎬 UI Preview (GIF)

<p align="center">
  <img src="https://media.giphy.com/media/13HgwGsXF0aiGY/giphy.gif" width="700"/>
</p>

---

## 📸 Screenshots

### 🏠 Dashboard
![Dashboard](docs/screenshots/01-dashboard.png)

### 🔍 Events Explorer
![Events](docs/screenshots/02-events.png)

### 🛡️ Mitigations
![Mitigations](docs/screenshots/03-mitigations.png)

### 🧠 Reputation
![Reputation](docs/screenshots/04-reputation.png)

### 📜 Audit Trail
![Audits](docs/screenshots/05-audits.png)

### ⚙️ Policy Management
![Policy](docs/screenshots/06-policy.png)

---

## 🧰 Tech Stack

- ⚛️ Next.js (App Router)
- 🎨 Tailwind CSS
- 🔗 REST API integration
- ⚡ Optimized operator UI/UX
- 🛡️ Security-first design

---

## 📦 Installation

```bash
git clone https://github.com/UZYNTRA-Security/uzyntra-ui.git
cd uzyntra-ui
npm install
````

---

## ▶️ Running the App

```bash
npm run dev
```

Open in browser:

```
http://localhost:3000
```

---

## 🔌 Backend Configuration

Browser requests go through the Next.js server-side API boundary at:

```
/api/admin/*
```

The Next.js server forwards those requests to the Rust Admin API. Configure server-only values with:

```
DATABASE_URL=postgresql://user:password@localhost:5432/uzyntra
DATABASE_POOL_SIZE=10
AUTH_PASSWORD_PEPPER=<at-least-32-random-characters>
AUTH_SESSION_SECRET=<at-least-32-random-characters>
AUTH_API_KEY_SECRET=<at-least-32-random-characters>
AUTH_MANAGEMENT_TOKEN_SECRET=<at-least-32-random-characters>
FIREWALL_ADMIN_URL=http://127.0.0.1:9090
FIREWALL_ADMIN_TOKEN=<admin-token>
BFF_ADMIN_TIMEOUT_MS=10000
BFF_MAX_BODY_BYTES=1048576
```

Do not put admin secrets in `NEXT_PUBLIC_*` variables or browser code.

The BFF requires a valid authenticated session cookie before forwarding admin requests. It only forwards the admin endpoints used by the current UI, rejects unexpected query parameters, limits request body size, blocks cross-origin writes, and applies an upstream timeout.

The BFF derives audit identity from the server-side session and forwards authenticated user, organization, session, request, route, method, and client context to the Rust Admin API. The browser cannot choose the admin actor, organization, permissions, or admin token.

---

## Authentication API

Native operator authentication APIs are available under:

```text
POST /api/auth/login
POST /api/auth/logout
GET /api/auth/me
```

Login verifies existing user credentials with the server-side Argon2id password utility, creates a PostgreSQL-backed session, and sets an HTTP-only session cookie. Failed login attempts are counted on `user_credentials`; five failed attempts lock the credential for 15 minutes. These endpoints do not enforce RBAC yet.

---

## RBAC Foundation

The control plane defines a permission catalog for future authorization:

```text
events.read
events.export
metrics.read
audits.read
mitigation.read
mitigation.create
mitigation.delete
reputation.read
reputation.reset
policy.read
policy.update
users.manage
roles.manage
api_keys.manage
service_accounts.manage
billing.manage
firewalls.manage
security_events.ingest
```

Default role templates are seeded as global roles:

```text
Owner
Security Admin
Analyst
Viewer
```

These roles are assigned to organization memberships through `user_roles`.

The server-side authorization engine resolves context from:

```text
validated user id
organization id
database membership
assigned roles
role permissions
```

It exposes exact-match permission helpers:

```text
getAuthorizationContext()
hasPermission()
hasAnyPermission()
hasAllPermissions()
```

The BFF maps each allowed admin route to a required permission before forwarding to the Rust Admin API. Organization-level routes such as metrics and audits use organization permissions. Firewall routes for events, policy, mitigations, and reputation require an active server-side firewall selection plus a firewall-scoped role assignment. Missing permissions return `403 Forbidden`; missing or invalid sessions return `401 Unauthorized`.

Firewall-instance scoped authorization extends the same role model with `firewall_instance_role_assignments`:

```text
organization membership
firewall instance
role
```

Future resource-aware routes can resolve:

```text
getFirewallAuthorizationContext()
hasFirewallPermission()
```

Those helpers verify the firewall belongs to the authenticated organization and derive permissions from roles assigned to that specific firewall instance. Organization-level permission alone does not grant firewall-instance access.

Authorization context is derived from the database and validated session identity, never from browser-supplied role, permission, organization, or firewall values. UI hiding is treated as a convenience only; server-side route handlers enforce tenant and firewall boundaries.

---

## Multi-Tenant SaaS Management

Authenticated operators can manage SaaS tenant resources through server-side APIs and console pages for:

```text
organizations
organization settings
members and invitations
firewall registration and enrollment
active firewall selection
service accounts
API keys
```

Organization switching updates the PostgreSQL-backed session after verifying active membership. The browser cannot override organization scope with arbitrary IDs.

Invitations and firewall enrollment use random one-time credentials. The plaintext value is returned only once; PostgreSQL stores only an HMAC hash using `AUTH_MANAGEMENT_TOKEN_SECRET`. Invitation and enrollment records are organization-scoped, expiring, revocable, and audited without credential values.

Firewall registration creates a disabled instance until enrollment succeeds. Enrollment activates the firewall, records installation metadata, creates or reactivates a machine service account, and returns one plaintext API key once for ingestion setup.

API key creation, rotation, revocation, and listing are organization-scoped. Rotation creates a replacement before revoking the old key in a transaction. Listing returns metadata only.

---

## Persistent Audit Foundation

The control plane stores immutable security activity in `audit_events`.

Audit events are append-only application records for:

```text
authentication events
authorization decisions
administrative actions
security changes
```

Audit writes use the server-only `createAuditEvent()` utility. The utility normalizes structured events, inserts them into PostgreSQL, and rejects sensitive metadata fields such as passwords, cookies, tokens, secrets, private keys, session values, and credential hashes.

The audit table is indexed for common SOC and compliance lookups:

```text
organization activity over time
user activity over time
service account activity over time
firewall activity over time
request correlation
```

Application code does not expose audit update or delete utilities. Future hardening options include database-level write-only permissions for app roles, table partitioning, external archival, retention policy, and WORM storage.

---

## API Key Foundation

Service accounts represent non-interactive machine identities owned by an organization. API keys may be attached to a service account and are generated as one-time plaintext secrets. The database stores only a display prefix and a server-side HMAC hash derived with `AUTH_API_KEY_SECRET`; plaintext API keys are never stored or returned after creation or rotation.

API keys support `active`, `revoked`, and `expired` runtime states, with `disabled` and `deleted` reserved by the lifecycle schema. Revocation records `revoked_at`, rotation creates a replacement key before revoking the old key, and API-key lifecycle changes write audit events without plaintext keys, hashes, tokens, or secrets.

The scoping foundation is organization ownership plus optional service-account ownership. Service-account roles reuse the same role and permission catalog instead of letting API keys carry browser-supplied scopes.

---

## Security Event Ingestion Foundation

The control plane stores SaaS security telemetry in PostgreSQL `security_events`. These records are separate from the Rust Firewall Engine's local SQLite `security_events`, so customer-facing analytics can evolve without changing runtime detection storage.

Security events are tenant-scoped by organization and firewall instance. The normalized event shape captures event type, attack type, severity, source IP, request path, HTTP method, user agent, country, confidence, action taken, request id, occurrence time, receipt time, and sanitized raw metadata.

The server-only ingestion utility validates that the firewall instance belongs to the target organization before insertion. Raw metadata rejects sensitive fields such as passwords, cookies, tokens, secrets, private keys, authorization headers, API keys, and credential hashes.

Firewall instances can submit events to:

```text
POST /api/ingest/security-events
Authorization: Bearer <service-account-api-key>
Content-Type: application/json
```

The ingestion route authenticates the service-account API key, rejects revoked, expired, disabled, and deleted keys, verifies the service account is active and belongs to the key's organization, validates firewall ownership, and then calls the server-side security-event utility. The browser must never send API keys to this endpoint.

Successful ingestion records `security_event.ingested`; failed ingestion records `security_event.ingestion_failed`. Audit records never include plaintext API keys, API-key hashes, authorization headers, cookies, tokens, or request credentials.

Future hardening should add per-API-key limits, per-firewall limits, replay detection, abuse detection, ingestion idempotency, queue buffering, and backpressure. This phase does not add dashboards, alerts, notifications, SIEM integrations, billing, onboarding UI, or Rust detection changes.

## Security Event Query APIs

Authenticated operators can query organization-scoped control-plane security events through:

```text
GET /api/security-events
GET /api/security-events/analytics
```

The list endpoint requires `events.read` and supports bounded filters for severity, attack type, action, source IP, HTTP method, request path, firewall instance, time window, limit, and cursor pagination. The analytics endpoint requires `metrics.read` and returns event totals, severity counts, top attack types, top source IPs, top routes, firewall distribution, and hourly timeline counts.

The browser does not provide organization scope. Both APIs derive organization identity from the server-side session and authorization context. When the session has an active firewall, event APIs force that firewall scope and reject cross-firewall substitution.

---

## Control Plane Database

The future UZYNTRA SaaS control plane uses PostgreSQL with Drizzle ORM. The Rust Firewall Engine keeps its existing SQLite storage; identity and SaaS metadata live on the Next.js control plane side.

Local development requires a PostgreSQL database configured by `DATABASE_URL`.

```bash
npm run db:generate
npm run db:migrate
```

The migrations create the database foundation for organizations, organization settings, users, credentials, email verification tokens, password reset tokens, memberships, invitations, roles, permissions, sessions, API keys, service accounts, service-account roles, audit actors, audit events, security events, firewall instances, firewall enrollment tokens, and firewall-instance role assignments. Lifecycle-aware entities use `status` plus `deleted_at` so security-sensitive records can be disabled or soft-deleted without losing history. Password hashes use server-side Argon2id utilities with `AUTH_PASSWORD_PEPPER` reserved for runtime credential operations. Session helpers use opaque random tokens, hashed storage, revocation timestamps, active organization context, optional active firewall context, and `AUTH_SESSION_SECRET` for server-side token hashing. API-key helpers generate one-time plaintext keys, store only prefixes and HMAC hashes using `AUTH_API_KEY_SECRET`, and audit lifecycle events. Management-token helpers hash invitation and enrollment credentials using `AUTH_MANAGEMENT_TOKEN_SECRET`. Security-event helpers normalize firewall telemetry, validate organization/firewall ownership, and reject secret metadata before insertion. The RBAC seed migration inserts the canonical permission catalog and default role templates idempotently. It does not implement billing, SAML, SCIM, OIDC, MFA behavior, email delivery, alerting, SIEM integrations, or Rust detection changes.

---

## 📁 Project Structure

```text
src/
 ├── app/
 │    ├── page.js                # Dashboard
 │    ├── events/page.js
 │    ├── mitigations/page.js
 │    ├── reputation/page.js
 │    ├── audits/page.js
 │    ├── policy/page.js
 │    └── layout.js
 │
 ├── components/
 │    ├── Sidebar.js
 │    ├── Topbar.js
 │    ├── PageHeader.js
 │    ├── MetricCard.js
 │    ├── SectionCard.js
 │    ├── SimpleTable.js
 │    ├── Badge.js
 │    └── EmptyState.js
 │
 └── lib/
      ├── api.js
      └── format.js
```

---

## 🧪 Development Notes

* Sidebar is **fixed layout (non-scrolling)**
* Main panel uses **independent scroll**
* Tables support **horizontal overflow**
* UI is optimized for **operator workflows**

---

## 🧭 Roadmap

* 🔐 Authentication & RBAC
* 📊 Analytics dashboards
* 📈 Charts & threat trends
* 🌐 SaaS multi-tenant support
* 🔔 Alerting & notifications

---

## 🤝 Contribution

Pull requests are welcome.

If you're building on top of UZYNTRA, feel free to fork and extend.

---

## 👨‍💻 Author

**[Muhammad Usama](https://www.linkedin.com/in/usamamatrix/)**
Cyber Security Analyst & Rust Backend Engineer

---

## ⭐ Support

If you like this project:

* ⭐ Star the repo
* 🍴 Fork it
* 🚀 Build something on top of it

---

## 🔗 Related Repository

👉 Backend:
[https://github.com/UZYNTRA-Security/uzyntra-api-firewall](https://github.com/UZYNTRA-Security/uzyntra-api-firewall)

---

## 🛡️ UZYNTRA

> *Control. Observe. Defend.*
