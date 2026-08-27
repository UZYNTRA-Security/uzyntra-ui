# Phase 8.2 - Advanced Detection Engine Evolution Planning

Status: documentation only. Do not modify code, create migrations, deploy infrastructure, change secrets, commit, push, or start implementation in this phase.

Phase 8.1 made security operations visible. Phase 8.2 improves the intelligence that feeds that operating layer.

Current flow:

```text
API Traffic
    |
    v
Detection Engine
    |
    v
Security Events
    |
    v
Alerts / Incidents
    |
    v
Security Operations Dashboard
```

Phase 8.2 target:

```text
Detection Engine
    |
    +--> behavioral analysis
    +--> attack correlation
    +--> adaptive confidence scoring
    +--> anomaly detection
    +--> threat context
```

Current capabilities:

- SQL injection detection.
- XSS detection.
- SSRF detection.
- API inventory learning.
- Schema anomaly detection.
- Authentication abuse detection.
- Object enumeration detection.
- Resource abuse detection.
- Response security observations.
- Detector scoring and confidence.
- Alert correlation.

The plan below builds on existing `security_events`, alert correlation, incident grouping, notification delivery observability, tenant isolation, and RBAC controls.

## 1. Behavioral Detection Engine

### Detection Goals

Behavioral detection should identify suspicious sequences that are weak or invisible as single requests.

Planned detection families:

| Family | Behavior | Example signal |
| --- | --- | --- |
| Unusual API access patterns | client accesses routes it rarely or never uses | first-time access to sensitive admin API |
| Endpoint discovery | many 404/405 responses or route probes | `/admin`, `/debug`, `/v1/users/export` scanning |
| Automated reconnaissance | high route diversity in a short window | many unique paths from one source/client |
| Abnormal request sequences | impossible or unusual call order | destructive action before expected read/init flow |
| Account behavior changes | new source, user agent, geo, route set, or velocity | service account suddenly enumerates users |
| API abuse patterns | high-volume or repeated sensitive action | repeated export, search, login, reset, token calls |

### Behavior Model

The first model should be deterministic and explainable:

```text
request context
  |
  +--> identity profile
  +--> route profile
  +--> tenant baseline
  +--> short-window activity
  |
  v
behavior signals
  |
  v
detector score + confidence + reason codes
```

Profiles:

| Profile | Scope | Purpose |
| --- | --- | --- |
| client profile | source IP, API key, service account, user where available | detect sudden changes and abusive velocity |
| route profile | API route, method, sensitivity, inventory status | detect sensitive access and discovery patterns |
| tenant profile | organization-level normal traffic shape | detect tenant-specific anomalies |
| firewall profile | gateway instance and route mix | detect edge-specific drift or abuse |

### Data Sources

Use existing data first:

- gateway request metadata.
- `security_events`.
- API inventory routes.
- detector IDs and confidence.
- auth and RBAC failure events.
- alerts and incidents.
- notification delivery failures where they indicate response reliability.

Future optional data:

- explicit request metrics rollups.
- identity session metadata.
- route sensitivity labels.
- IP reputation and ASN enrichment.
- customer-maintained allowlists.

### Scoring Approach

Each behavior detector emits:

- `detector_id`
- `behavior_signal`
- `score`
- `confidence`
- `severity`
- `reason_codes`
- sanitized metadata

Initial score formula:

```text
behavior_score =
  velocity_weight
+ novelty_weight
+ sensitivity_weight
+ failure_weight
+ detector_overlap_weight
- known_good_adjustment
- suppression_adjustment
```

Example:

```text
new source IP                  +10
new user agent                 +5
50 unique routes in 5 minutes  +25
20 authorization failures      +20
sensitive route touched        +20
known service account baseline -15
```

### False-Positive Controls

Controls must be available before broad enforcement:

- tenant-specific baselines.
- route sensitivity configuration.
- detector confidence thresholds.
- customer allowlists with expiration.
- suppression rules.
- analyst feedback.
- sampling and observe-only mode.
- time-window caps to avoid one burst dominating risk.

Behavioral detections should start in monitor mode, feed security operations dashboards, and only become blocking candidates after enough evidence is collected.

## 2. Advanced Risk Scoring

### Current and Future Model

Current:

```text
single event score
```

Future:

```text
event risk
+ user/client risk
+ API risk
+ tenant risk
= overall threat score
```

### Risk Components

| Component | Inputs | Purpose |
| --- | --- | --- |
| event risk | detector score, severity, confidence, action, metadata | score the immediate request |
| user/client risk | recent failures, route diversity, source changes, identity type | score the acting identity or source |
| API risk | route sensitivity, inventory status, exposure, auth requirements | score the target API surface |
| tenant risk | active incidents, alert pressure, posture score, policy coverage | score current tenant exposure |

### Proposed Formula

```text
overall_threat_score =
  event_risk * 0.45
+ client_risk * 0.25
+ api_risk * 0.20
+ tenant_risk * 0.10
```

Normalize each component to `0..100`.

The formula should remain explainable and versioned:

```json
{
  "score_version": "8.2.v1",
  "overall": 82,
  "components": {
    "event": 90,
    "client": 75,
    "api": 85,
    "tenant": 55
  },
  "reason_codes": [
    "high_confidence_detector",
    "sensitive_route",
    "route_enumeration",
    "recent_auth_failures"
  ]
}
```

### Confidence Model

Confidence should answer: "How much does UZYNTRA trust this detection?"

Inputs:

- detector certainty.
- number of corroborating signals.
- baseline quality.
- request context quality.
- historical false-positive rate.
- tenant-specific tuning.

Confidence bands:

| Confidence | Meaning | Action |
| --- | --- | --- |
| 0-39 | weak signal | observe and aggregate only |
| 40-69 | plausible | create event, use low/medium severity |
| 70-89 | strong | alert when score and severity justify |
| 90-100 | high confidence | alert and incident candidate |

### Severity Mapping

Severity should consider score and confidence together:

| Score | Confidence | Severity |
| --- | --- | --- |
| 0-24 | any | low |
| 25-49 | under 70 | low |
| 25-49 | 70+ | medium |
| 50-74 | under 60 | medium |
| 50-74 | 60+ | high |
| 75-100 | under 50 | high |
| 75-100 | 50+ | critical |

Critical severity should require either high confidence or high-impact API context.

## 3. Attack Correlation Engine

### Correlation Scope

Correlate across:

- multiple requests.
- multiple endpoints.
- multiple detectors.
- time windows.
- identities.
- source IPs and ASNs.
- firewall instances.
- organization context.

### Correlation Windows

| Window | Purpose |
| --- | --- |
| 1 minute | burst abuse, scanners, credential attacks |
| 5 minutes | route enumeration, object enumeration, endpoint discovery |
| 15 minutes | multi-step attack sequences |
| 1 hour | campaign-level activity and low-rate abuse |
| 24 hours | tenant posture and repeat offender trends |

### Correlation Keys

Use one or more keys:

- `organization_id`
- `firewall_instance_id`
- `source_ip_hash` or sanitized source reference.
- API key/service account/user identity.
- route or route group.
- detector family.
- user agent fingerprint.
- ASN/geography when available.

### Example: BOLA / Account Takeover Pattern

Single event:

```text
GET /users?id=1
```

Combined pattern:

```text
1000 IDs accessed
+ failed auth attempts
+ new device or source
+ sensitive user API
```

Result:

```text
possible account takeover or BOLA
severity: critical
confidence: high
incident candidate: yes
```

### Correlation Outputs

The correlation engine should produce either:

- enriched `security_events`.
- correlated alert candidates.
- incident grouping hints.
- detector statistics.

Do not create opaque correlation payloads. Every correlation must have reason codes and enough context for analysts to understand why it fired.

## 4. API Abuse Intelligence

### Planned Abuse Detections

| Abuse Type | Signals | Response |
| --- | --- | --- |
| credential stuffing | high login failures, source diversity, repeated usernames | event, alert, possible rate-limit recommendation |
| token replay | same token from impossible locations or many clients | high severity event, incident candidate |
| excessive enumeration | sequential IDs, high cardinality object access | high confidence behavioral event |
| scraping behavior | high volume reads, predictable pagination, low mutation ratio | medium/high risk event |
| automated scanners | route probing, signature user agents, high 404/405 | scanner classification |
| malicious bots | bot-like velocity, reputation context, abnormal headers | bot risk event |

### Abuse Reason Codes

Standardize reason codes:

- `route_enumeration`
- `object_enumeration`
- `credential_attack`
- `token_replay_suspected`
- `scanner_behavior`
- `suspicious_velocity`
- `sensitive_route_access`
- `baseline_deviation`
- `known_bad_reputation`
- `new_identity_context`

Reason codes make dashboards, alerts, and future tuning easier.

## 5. Detection Learning Layer

### Baseline Learning

Baseline normal behavior per tenant/firewall/route:

- route frequency.
- method mix.
- status code mix.
- typical request rate.
- typical source/client count.
- detector frequency.
- sensitive route access patterns.

The first learning layer should use bounded rolling windows, not complex machine learning:

```text
current window
  compared to
rolling baseline
  produces
deviation score
```

### Tenant-Specific Learning

Every tenant has different APIs. Learning must be tenant-local:

- no cross-tenant behavioral profiles.
- no shared raw metadata.
- no tenant data used to score another tenant.
- global detector defaults allowed only if they do not contain tenant data.

### Privacy and Safety

Security requirements:

- no sensitive request bodies.
- no raw credentials.
- no full authorization headers.
- hash or truncate identifiers where possible.
- bounded memory and bounded retention.
- per-tenant isolation for baselines.
- clear opt-out or observe-only controls for sensitive tenants.

### Data Model Proposal

No migrations in this phase. Future models may include:

| Model | Purpose |
| --- | --- |
| `behavior_baselines` | route/client/tenant normal behavior summaries |
| `detector_feedback` | analyst labels and false-positive feedback |
| `correlation_findings` | explainable multi-event correlation results |
| `risk_score_snapshots` | versioned score components and trend inputs |

## 6. Threat Context Enhancement

### Context Sources

Add enrichment sources in layers:

| Context | Use | Storage |
| --- | --- | --- |
| IP reputation | known scanner, proxy, abuse source | cached reputation score, source reference |
| ASN | hosting provider, residential, cloud, VPN | ASN number/name, category |
| geo context | unusual country/region, impossible travel | coarse country/region only |
| user-agent intelligence | scanner/tool/browser classification | normalized family/category |
| known scanner signatures | Nuclei, sqlmap, masscan-like probes | signature ID and confidence |

### Privacy Rules

- Do not store sensitive personal data beyond operational need.
- Prefer coarse geo over precise location.
- Store enrichment source and timestamp for auditability.
- Expire reputation data; do not treat stale context as high confidence.
- Allow tenant-level controls for enrichment visibility.

### Threat Context Output

Example event metadata:

```json
{
  "threat_context": {
    "ip_reputation": "suspicious",
    "asn_category": "hosting",
    "user_agent_family": "scanner",
    "known_signature": "sqlmap-like",
    "context_confidence": 82,
    "enriched_at": "2026-08-24T00:00:00Z"
  }
}
```

## 7. Detector Management

### Detector Lifecycle

Detector states:

| State | Meaning |
| --- | --- |
| draft | detector definition exists but is not active |
| observe | records telemetry only |
| alerting | creates alert candidates when thresholds match |
| blocking candidate | eligible for policy-controlled blocking |
| deprecated | retained for history, not used for new detections |

### Detector Controls

Future management should support:

- enable/disable by tenant and firewall.
- detector exceptions by route/method.
- confidence thresholds.
- severity overrides.
- observe-only mode.
- test mode for detector updates.
- detector version tracking.
- audit history for every tuning change.

### Tuning Workflow

```text
detection fires
  |
  v
analyst reviews event/alert
  |
  +--> confirmed true positive
  |      v
  |    strengthen confidence/correlation
  |
  +--> false positive
         v
       suppression, exception, or threshold adjustment
```

Detector changes must not silently affect every tenant. Start with tenant-scoped tuning, then promote safe defaults when validated.

## 8. False Positive Management

### Suppression Rules

Suppression should be explicit, scoped, and temporary by default.

Scope options:

- organization.
- firewall.
- route.
- detector ID.
- source/client identity.
- severity threshold.
- time window.

Rule requirements:

- owner.
- reason.
- expiration.
- audit event.
- preview of affected detections where possible.

### Analyst Feedback

Feedback labels:

- true positive.
- false positive.
- expected behavior.
- duplicate.
- needs tuning.
- customer exception.

Feedback should feed:

- detector quality metrics.
- false-positive rate.
- confidence adjustment proposals.
- suppression recommendations.

### Allowlists

Allowlists must be narrow:

- never global by default.
- expire automatically unless explicitly renewed.
- cannot bypass authentication or tenant isolation.
- should reduce score/confidence, not erase evidence completely.

## 9. Performance Architecture

### Request Path Constraints

Detection must not materially increase gateway latency.

Design principles:

- keep synchronous checks cheap.
- use bounded in-memory windows.
- move heavy correlation to async workers.
- cap metadata size.
- use approximate counters where acceptable.
- drop enrichment gracefully when providers fail.

### Streaming Analysis

Recommended split:

```text
request path
  |
  +--> fast detectors
  +--> local event persistence
  |
  v
async analysis worker
  |
  +--> correlation
  +--> baseline updates
  +--> enrichment
  +--> alert candidates
```

### Caching and Memory Limits

Use per-tenant/firewall bounded caches:

- LRU maps for short-window counters.
- TTL buckets for velocity.
- maximum identities tracked per tenant.
- maximum routes tracked per tenant.
- memory pressure fallback to event-only mode.

### Database and Aggregation

Phase 8.2 should avoid unbounded raw-event scans:

- write detector/correlation outputs as events or compact findings.
- use Phase 8.1 aggregation APIs for dashboards.
- add aggregate tables only when validated by volume.
- index any future detector/correlation tables by organization and time.

## 10. Enterprise Security Alignment

### OWASP API Security Top 10 Mapping

| OWASP Area | Phase 8.2 Coverage |
| --- | --- |
| Broken Object Level Authorization | object enumeration, route/user correlation |
| Broken Authentication | credential stuffing, token replay, auth abuse |
| Broken Object Property Level Authorization | sensitive route and schema anomaly context |
| Unrestricted Resource Consumption | resource abuse and velocity scoring |
| Broken Function Level Authorization | endpoint discovery and abnormal route access |
| Unrestricted Access to Sensitive Business Flows | scraping, automation, abuse intelligence |
| Server Side Request Forgery | existing SSRF detector with context/correlation |
| Security Misconfiguration | response observations and posture linkage |
| Improper Inventory Management | API inventory learning and shadow route detection |
| Unsafe Consumption of APIs | future upstream/provider anomaly context |

### NIST CSF Mapping

| Function | Phase 8.2 Contribution |
| --- | --- |
| Identify | API risk and tenant baselines |
| Protect | detector tuning and policy recommendations |
| Detect | behavioral, anomaly, and correlation detections |
| Respond | higher-quality alerts and incident grouping |
| Recover | incident evidence and trend analysis for hardening |

### SOC Monitoring Requirements

Phase 8.2 must improve:

- alert quality.
- correlation context.
- signal explainability.
- false-positive tracking.
- detector health.
- analyst feedback loops.
- threat trend visibility in Phase 8.1 dashboards.

## Implementation Sequence Recommendation

Do not build all advanced detection at once. Recommended Phase 8.2 implementation slices:

1. Detector contract and reason-code standardization.
2. Risk scoring v2 with component breakdown.
3. Short-window behavioral counters for reconnaissance and enumeration.
4. Correlation worker for multi-event findings.
5. False-positive feedback and suppression workflow.
6. Detector management and tenant-scoped tuning.
7. Threat context hooks prepared for Phase 8.3 enrichment.

Each slice should include tests, performance validation, and dashboard visibility.

## Release Gate Proposal

Phase 8.2 implementation should be considered ready only when:

- detector outputs remain tenant-scoped.
- advanced scores are explainable.
- false-positive controls exist for new noisy detections.
- gateway latency impact is measured.
- memory bounds are enforced.
- existing Phase 5/6/8.1 tests pass.
- no sensitive request data is stored.
- alerts/incidents consume new scores without regressions.
- dashboards show new detector quality and risk data.

## Phase 8.2 Status

PHASE 8.2 PLANNING STATUS: READY

This document defines the Advanced Detection Engine Evolution plan only. No application code was modified, no migrations were created, no infrastructure was deployed, no secrets were changed, no commits or pushes were made, implementation was not started, and Phase 8.3 was not started.

Recommended next sequence:

1. Phase 8.2 implementation.
2. Phase 8.3 threat intelligence layer.
3. Phase 8.4 zero trust API security.
