# Phase 8.1 - Security Operations Foundation Planning

Status: documentation only. Do not modify application code, modify database schema, create migrations, deploy infrastructure, change environments, commit, push, release, or start Phase 8.2 in this phase.

UZYNTRA already has the core security data plane:

- `security_events`
- `alerts`
- `incidents`
- `notification_deliveries`
- API inventory
- detection scoring
- tenant isolation

Phase 8.1 must build on those primitives instead of creating a parallel analytics system. The goal is to define the Security Operations Foundation that turns existing events, alerts, incidents, inventory, and delivery state into operator-ready security views.

## 1. Security Operations Dashboard Architecture

### Product Areas

| Area | Audience | Purpose |
| --- | --- | --- |
| Executive security overview | Owners, CISOs, tenant admins | Summarize exposure, risk, incident pressure, and protection value |
| Analyst dashboard | Security analysts/operators | Investigate active threats, alerts, incidents, and suspicious sources |
| Tenant security posture view | Tenant admins and internal operators | Show tenant-specific security maturity, coverage, and gaps |
| Real-time event monitoring | Analysts and responders | Track current attack activity and detection flow |
| Incident overview | Responders and managers | Track active incidents, severity, ownership, and resolution progress |

### Page Structure

| Page | Route | Primary data sources |
| --- | --- | --- |
| Security Dashboard | `/security-dashboard` | `security_events`, `alerts`, `incidents`, API inventory |
| Security Posture | `/security-posture` | API inventory, alert rules, firewall inventory, security event aggregates |
| Threat Analytics | `/threat-analytics` | `security_events`, detector statistics, attack categories |
| Security Trends | `/security-trends` | hourly/daily aggregates, incidents, alerts, delivery health |
| Incident Operations | existing `/incidents` plus future operations panel | `incidents`, `incident_alerts`, `alerts` |

The first implementation should add pages in the existing Next.js control plane and continue using the established API/RBAC patterns. Do not introduce a separate BI app or analytics database until event volume proves it is necessary.

### Component Model

| Component | Purpose | Visual design |
| --- | --- | --- |
| Risk score card | Current tenant/platform risk summary | large numeric score, severity color, trend delta |
| Attack volume timeline | Events over time by severity/action | stacked area or stacked bar chart |
| Blocked requests chart | Protection impact over time | line chart with blocked/allowed/monitored series |
| Top threats bar chart | Top attack types, detectors, source countries/IPs | horizontal bars sorted by count/risk |
| Detector confidence chart | Confidence and score distribution | histogram or grouped bars |
| Incident funnel | Open, acknowledged, investigating, resolved | segmented bar |
| API exposure map | Known, shadow, sensitive, risky routes | grouped bars and table |
| Alert delivery health | Delivered, retrying, failed notifications | stacked bars |
| Real-time event stream | Recent security detections | dense table with filters |
| Tenant posture checklist | Policy coverage and control gaps | progress bars and checklist rows |

Graphs and bars should be first-class. Use bar charts for categorical comparisons, line charts for time trends, stacked bars for severity/action composition, and compact progress bars for posture coverage.

### Data Flow

```text
Rust gateway
  |
  | telemetry
  v
POST /api/ingest/security-events
  |
  v
security_events
  |
  +--> alert evaluator
  |      |
  |      v
  |    alerts -> incidents -> notification_deliveries
  |
  +--> API inventory updates
  |
  v
aggregation layer
  |
  v
security metrics
  |
  v
dashboard APIs
  |
  v
Security Operations UI
```

## 2. Security Metrics Model

### Notification Delivery Operations

Notification delivery must be a first-class security operations signal. A security platform is only operationally useful if alerts and incidents reliably reach the people and systems expected to respond.

```text
Security Event
      |
      v
Alert Engine
      |
      v
Incident Engine
      |
      v
Notification Outbox
      |
      v
notification_deliveries
      |
      +----------------+
      |                |
      v                v
Webhook          Email / SIEM
```

Delivery health should appear in the SOC dashboard, incident operations view, and integration health view.

Delivery states:

| State | Meaning | Operator action |
| --- | --- | --- |
| Pending | Waiting for delivery | Monitor age and queue depth |
| Delivered | Successfully sent | None |
| Retrying | Temporary failure | Watch retry age/provider pattern |
| Failed | Permanent failure | Review integration configuration |
| Dead Letter | Requires operator action | Triage, fix, replay or close |

Delivery health metrics:

| Metric | Definition | Source |
| --- | --- | --- |
| total notifications | total delivery attempts created | `notification_deliveries` |
| successful deliveries | deliveries with status `delivered` | `notification_deliveries.status` |
| failed deliveries | deliveries with permanent failure state | `notification_deliveries.status` |
| retry count | total retry attempts and currently retrying deliveries | `notification_deliveries.attemptCount`, status |
| average delivery latency | average time from creation to delivery | `createdAt`, `deliveredAt` or future equivalent |
| dead letter count | deliveries requiring manual action | failed/exhausted retry state |
| provider failure rate | failures grouped by channel/provider | `notification_deliveries.channelId`, status |

Alert Reliability Score:

```text
successful deliveries / total delivery attempts
```

Example widget:

```text
Notification Delivery Health

Success       98.7%
Failed         1.3%

Webhook
  450 sent
  443 success
  7 retrying

SIEM
  120 sent
  120 success

Alert Reliability
  Enterprise A: 99.2%
  Last Failure: Webhook timeout
  Current Status: Healthy
```

Security requirements:

- Never store webhook secrets in delivery records.
- Show only masked integration names in dashboard rows.
- Enforce tenant isolation on delivery history.
- Require RBAC:
  - `integrations.manage` for integration configuration and replay controls.
  - `alerts.read` for alert-linked delivery visibility.
  - `incidents.read` for incident-linked delivery visibility.
- Audit every integration create/update/delete, delivery replay, disable, and failure-state override.
- Do not expose full webhook URLs, signing secrets, request headers, or payload secrets in dashboard views.

### Gateway Metrics

| Metric | Definition | Source |
| --- | --- | --- |
| request volume | total gateway requests by tenant/firewall/time bucket | gateway telemetry or future request metrics |
| latency | p50/p95/p99 gateway latency | gateway telemetry, future metric events |
| errors | gateway `4xx`/`5xx` by route/upstream | gateway telemetry |
| blocked requests | events with action `blocked` | `security_events.actionTaken` |
| detection rate | detections per 1,000 requests | security events divided by request volume |
| top protected routes | highest volume/risk routes | API inventory + events |

### Control Plane Metrics

| Metric | Definition | Source |
| --- | --- | --- |
| API availability | control-plane route health and error rates | provider logs + future app metrics |
| ingestion success/failure | successful and rejected ingest attempts | `audit_events`, ingestion API responses |
| authentication failures | failed logins/session errors | `audit_events` |
| authorization failures | RBAC denials and forbidden access attempts | `audit_events` |
| BFF admin activity | admin proxy operations by route/user/firewall | `audit_events` |

### Security Metrics

| Metric | Definition | Source |
| --- | --- | --- |
| critical findings | count of critical events and open critical alerts | `security_events`, `alerts` |
| attack categories | attack types by time, tenant, firewall | `security_events.attackType` |
| detector confidence | confidence distribution by detector ID | `security_events.confidence` |
| risk score | weighted score combining severity, event score, unresolved incidents, exposure | aggregates over events/alerts/incidents/inventory |
| incident trends | incident volume, resolution time, severity mix | `incidents`, `incident_alerts` |
| alert pressure | open/acknowledged/resolved alerts and dedupe counts | `alerts` |
| alert reliability score | successful deliveries divided by total delivery attempts | `notification_deliveries` |
| delivery failure rate | failed/retrying deliveries by provider/channel | `notification_deliveries` |

### Tenant Metrics

| Metric | Definition | Source |
| --- | --- | --- |
| API exposure | known, shadow, deprecated, sensitive, risky routes | API inventory |
| security posture score | weighted control coverage and active risk | inventory + events + alert rules |
| policy coverage | routes with explicit behavior/rate/override policies | API inventory + policy data |
| detector coverage | events/routes covered by supported detectors | `security_events.detectorId`, API inventory metadata |
| response readiness | alert rules, integrations, incident activity | alert rules, notification channels, incidents |

## 3. Analytics Pipeline Design

### Pipeline

```text
security_events
        |
        v
aggregation layer
        |
        v
security metrics
        |
        v
dashboard
```

### Real-Time Metrics

Real-time dashboards should query recent raw tables with tight limits:

- last 5 minutes security events.
- last 15 minutes severity/action counts.
- open critical alerts.
- active incidents.
- recent ingestion failures.
- recent notification delivery failures.

Use raw queries initially because they are operationally simple and already tenant-scoped. Apply hard limits and indexes to avoid dashboard abuse.

### Hourly Aggregation

Hourly aggregates should summarize:

- event count by organization, firewall, severity, action, attack type, detector ID.
- score average/max/p95.
- unique source IP count.
- blocked vs monitored ratio.
- alert count and incident count.
- notification delivery success/failure.
- retry count, dead letter count, and provider failure rate.

Hourly metrics are the primary source for charts covering 24 hours to 14 days.

### Daily Reports

Daily aggregates should summarize:

- risk score by tenant.
- posture score.
- top attack categories.
- most targeted routes.
- detector mix.
- incident open/resolved counts.
- mean time to acknowledge and resolve.
- notification delivery reliability.
- alert reliability score by tenant and integration type.

Daily metrics power executive views, trend pages, and future reports.

### Retention Strategy

| Data | Initial retention |
| --- | --- |
| raw `security_events` | 90 days hot data |
| raw `audit_events` | 180 days |
| raw alerts/incidents | 1 year or longer |
| hourly metrics | 180 days |
| daily metrics | 2 years |
| dashboard snapshots | 1 year |

Retention must be tenant-aware and must not delete open incident evidence before the incident is resolved.

## 4. Database Design Proposal

No migrations in Phase 8.1. These are future model proposals only.

### `security_metrics`

Purpose:

- Store hourly/daily event aggregates for fast dashboards.

Suggested fields:

- `id`
- `organization_id`
- `firewall_instance_id`
- `bucket_start`
- `bucket_size`
- `severity`
- `attack_type`
- `detector_id`
- `action_taken`
- `event_count`
- `blocked_count`
- `unique_source_count`
- `avg_score`
- `max_score`
- `p95_score`
- `created_at`

Indexes:

- `(organization_id, bucket_start desc)`
- `(organization_id, firewall_instance_id, bucket_start desc)`
- `(organization_id, severity, bucket_start desc)`
- `(organization_id, attack_type, bucket_start desc)`
- `(organization_id, detector_id, bucket_start desc)`

Tenant isolation:

- Every query must require `organization_id`.
- Firewall filters must verify firewall ownership.

Retention:

- Hourly: 180 days.
- Daily rollup: 2 years.

### `tenant_security_scores`

Purpose:

- Persist daily posture/risk scores for tenant trend lines and executive summaries.

Suggested fields:

- `id`
- `organization_id`
- `score_date`
- `risk_score`
- `posture_score`
- `critical_open_alerts`
- `active_incidents`
- `api_exposure_score`
- `policy_coverage_score`
- `detector_coverage_score`
- `response_readiness_score`
- `score_inputs`
- `created_at`

Indexes:

- `(organization_id, score_date desc)`
- `(organization_id, risk_score desc)`
- `(organization_id, posture_score desc)`

Tenant isolation:

- Organization-scoped only.

Retention:

- 2 years.

### `detection_statistics`

Purpose:

- Track detector quality, confidence, and volume over time.

Suggested fields:

- `id`
- `organization_id`
- `firewall_instance_id`
- `detector_id`
- `bucket_start`
- `bucket_size`
- `event_count`
- `avg_confidence`
- `avg_score`
- `false_positive_count`
- `resolved_count`
- `incident_linked_count`
- `created_at`

Indexes:

- `(organization_id, detector_id, bucket_start desc)`
- `(organization_id, firewall_instance_id, detector_id, bucket_start desc)`

Retention:

- 1 year hot aggregate.

### `dashboard_snapshots`

Purpose:

- Store precomputed executive dashboard payloads for fast page load and reporting.

Suggested fields:

- `id`
- `organization_id`
- `snapshot_type`
- `snapshot_at`
- `window_start`
- `window_end`
- `payload`
- `created_at`

Indexes:

- `(organization_id, snapshot_type, snapshot_at desc)`

Tenant isolation:

- Payload must be derived from a single organization only.
- Do not store cross-tenant summaries unless explicitly scoped to internal platform operators with a separate permission.

Retention:

- 1 year.

### `notification_delivery_metrics`

Purpose:

- Proposed future aggregate table for delivery reliability, retry pressure, provider failure rates, and alert reliability scoring.

Suggested fields:

- `id`
- `organization_id`
- `channel_id`
- `provider_type`
- `bucket_start`
- `bucket_size`
- `total_count`
- `delivered_count`
- `pending_count`
- `retrying_count`
- `failed_count`
- `dead_letter_count`
- `total_attempt_count`
- `avg_delivery_latency_ms`
- `last_failure_reason`
- `created_at`

Indexes:

- `(organization_id, bucket_start desc)`
- `(organization_id, channel_id, bucket_start desc)`
- `(organization_id, provider_type, bucket_start desc)`

Tenant isolation:

- Organization-scoped only.
- Channel IDs must be verified against the same organization before filtering.

Retention:

- Hourly: 180 days.
- Daily rollup: 2 years.

## 5. API Design Proposal

Future endpoints should follow existing auth/RBAC and response patterns.

| Endpoint | Purpose | Permission |
| --- | --- | --- |
| `GET /api/security/dashboard` | executive/analyst summary cards and chart payloads | `security_events.read`, `alerts.read`, `incidents.read` |
| `GET /api/security/metrics` | time-series and aggregate metrics | `security_events.read` |
| `GET /api/security/trends` | daily/hourly trends | `security_events.read` |
| `GET /api/security/posture` | tenant posture score and coverage gaps | `security_events.read` plus inventory read |
| `GET /api/security/top-threats` | top attack types, detectors, sources, routes | `security_events.read` |
| `GET /api/security/realtime` | recent event stream and live counters | `security_events.read` |
| `GET /api/security/incidents/overview` | incident operations summary | `incidents.read` |
| `GET /api/security/notification-deliveries` | delivery history, retry state, failures | `alerts.read` or `incidents.read` |
| `GET /api/security/notification-health` | delivery reliability score and provider health | `alerts.read`, `incidents.read` |

### Query Parameters

Support:

- `organization_id` only for internal platform operators. Normal tenant users infer organization from session.
- `firewall_instance_id`
- `since`
- `until`
- `bucket`
- `severity`
- `attack_type`
- `detector_id`
- `action_taken`
- `route`
- `channel_id`
- `provider_type`
- `delivery_status`
- `limit`
- `cursor`

Rules:

- Default window: 24 hours.
- Maximum raw-event window: 7 days.
- Maximum aggregate window: 1 year.
- Default limit: 100.
- Maximum limit: 500.
- Cursor pagination for tables.
- Bucket values limited to `minute`, `hour`, `day`.
- Every endpoint must enforce tenant isolation before querying.

### RBAC Requirements

Add permissions later only if current catalog is too coarse:

- `security.dashboard.read`
- `security.metrics.read`
- `security.posture.read`
- `security.platform.read` for internal cross-tenant platform views only.

Do not give cross-tenant dashboard access to normal tenant users.

## 6. UI Design Proposal

### `/security-dashboard`

Primary purpose:

- SOC landing page for current risk, attack pressure, and incident state.

Widgets:

- Current risk score card.
- Open critical alerts card.
- Active incidents card.
- Blocked requests card.
- Attack volume stacked bar chart.
- Severity trend line chart.
- Top attack categories horizontal bar chart.
- Recent high-confidence detections table.
- Incident funnel segmented bar.
- Notification Delivery Health stacked bar.
- Alert Reliability Score card.

Filters:

- time range.
- organization context.
- firewall.
- severity.

### `/security-posture`

Primary purpose:

- Tenant maturity and exposure view.

Widgets:

- posture score progress bar.
- API exposure grouped bars: known, shadow, sensitive, risky.
- policy coverage progress bars.
- detector coverage bars.
- alert/integration readiness checklist.
- risky routes table.
- uncovered routes table.

Filters:

- firewall.
- route status.
- detector coverage.

### `/threat-analytics`

Primary purpose:

- Investigate attacks, detectors, source patterns, and route targeting.

Widgets:

- attack category stacked bars.
- detector confidence histogram.
- top source IP/country horizontal bars.
- targeted routes bar chart.
- score distribution chart.
- detector trend line chart.
- event table with expandable metadata.

Filters:

- time range.
- attack type.
- detector ID.
- action taken.
- source IP.
- route.

### `/security-trends`

Primary purpose:

- Long-term executive and analyst trends.

Widgets:

- risk score trend line.
- posture score trend line.
- daily blocked requests bars.
- incident open/resolved trend.
- mean time to acknowledge/resolve.
- notification delivery reliability stacked bars.
- alert reliability score trend.
- top recurring threats table.

Filters:

- 7 days.
- 30 days.
- 90 days.
- custom range.

### Visual Guidelines

- Use line charts for trends over time.
- Use stacked bars for severity/action composition.
- Use horizontal bars for ranked top threats.
- Use progress bars for posture and coverage.
- Use tables for event-level investigation.
- Keep charts tenant-scoped and filter-aware.
- Avoid decorative charts that do not support decisions.

### Notification Delivery Widgets

Add a dedicated operations group:

| Widget | Route/page | Visual |
| --- | --- | --- |
| Notification Delivery Health | `/security-dashboard`, `/security-trends` | stacked bar: delivered, retrying, failed, dead letter |
| Alert Reliability Score | `/security-dashboard`, `/security-posture` | percentage card with trend delta |
| Provider Failure Rate | `/threat-analytics` or future integration health view | horizontal bar by provider/channel |
| Retry Queue | incident operations panel | table sorted by oldest retry |
| Dead Letter Queue | incident operations panel | table requiring operator action |

The first implementation can use existing `notification_deliveries` rows. Future implementation can move repeated chart queries to `notification_delivery_metrics`.

## 7. Performance Design

### Large Event Volume

Use a staged approach:

1. Raw indexed queries for short windows.
2. Hourly aggregates for charts after event volume grows.
3. Daily aggregates for executive trends.
4. Read replica or analytics warehouse only if Postgres load becomes a bottleneck.

### Query Optimization

Principles:

- Always filter by `organization_id`.
- Filter by `firewall_instance_id` when selected.
- Use time-bounded queries.
- Avoid unbounded group-by on raw `security_events`.
- Use existing indexes first.
- Add aggregate tables before adding complex dashboard queries.

Existing useful indexes include organization/time, firewall/time, severity/time, attack type/time, detector, and API route indexes on `security_events`.

### Caching

| Data | Cache strategy |
| --- | --- |
| real-time cards | no cache or short 15-30 second cache |
| hourly charts | 1-5 minute cache |
| daily trends | 15-60 minute cache |
| posture score | recompute daily or on material security changes |
| raw event tables | no shared cache; cursor pagination |
| notification delivery health | 1-5 minute cache for aggregates; no cache for dead-letter action tables |

Cache keys must include organization, firewall, time range, filters, user permission scope, and route version.

### Tenant Isolation

- Never compute dashboards from multiple tenants unless the user has explicit internal platform permission.
- Do not cache tenant-scoped data under global keys.
- Do not expose raw metadata containing secrets.
- Sanitize event metadata before both storage and display.

## 8. Security Review

| Risk | Mitigation |
| --- | --- |
| data leakage between tenants | require organization-scoped auth context on every endpoint; include organization in cache keys |
| sensitive event exposure | continue metadata sanitization; hide raw headers/cookies/tokens |
| dashboard abuse | apply rate limits, max windows, max limits, and aggregate queries |
| excessive queries | introduce hourly/daily aggregate tables before wide dashboard rollouts |
| privilege escalation | require dashboard/read/posture permissions; do not infer platform access |
| cross-firewall leakage | verify firewall ownership on every filter |
| misleading metrics | define score formulas and show freshness/window in UI |
| alert fatigue | separate operational counters from actionable incident queues |
| privacy concerns | avoid storing request bodies; redact identifiers where possible |
| delivery secret exposure | never show webhook secrets, signing headers, full URLs, or payload secrets |

## 8.1.1 Notification Delivery Observability

Phase 8.1 implementation should include notification delivery observability as part of the foundation, before Phase 8.2.

Scope:

- delivery metrics.
- retry visibility.
- failure analysis.
- integration health score.
- delivery analytics API.
- dashboard widgets.

Minimum implementation target:

1. Query existing `notification_deliveries` by organization.
2. Show delivered, pending, retrying, failed, and dead-letter counts.
3. Compute Alert Reliability Score.
4. Group delivery health by provider/channel.
5. Surface oldest retrying and failed deliveries.
6. Mask integration/channel names where needed.
7. Require `alerts.read` or `incidents.read` for read-only visibility.
8. Require `integrations.manage` for replay/disable/fix actions if those actions are later added.
9. Audit every integration change and any future delivery replay.

This makes alert delivery reliability visible alongside security events, alerts, and incidents.

## 9. Enterprise Features Roadmap

### Phase 8.2 - Advanced Detection Engine

Builds on:

- detector statistics.
- score trends.
- false-positive feedback.
- detector confidence charts.

Expected outcome:

- better detector tuning, adaptive thresholds, and detector health reporting.

### Phase 8.3 - Threat Intelligence

Builds on:

- top threat views.
- source IP/country/category trends.
- attack type aggregation.

Expected outcome:

- threat intel enrichment, reputation overlays, and campaign detection.

### Phase 8.4 - Zero Trust API Security

Builds on:

- API exposure.
- policy coverage.
- route behavior and inventory posture.

Expected outcome:

- route-level trust policies, identity-aware API controls, and continuous policy validation.

### Phase 8.5 - Compliance Dashboard

Builds on:

- dashboard snapshots.
- audit logs.
- incidents.
- posture scoring.

Expected outcome:

- compliance evidence, control coverage, audit reports, and security posture exports.

## Phase 8.1 Status

PHASE 8.1 PLANNING STATUS: READY

This plan defines the Security Operations Foundation without implementation. No application code was modified, no database schema was modified, no migrations were created, no infrastructure was deployed, no environments were changed, no commits/releases were made, and Phase 8.2 was not started.

Recommended next sequence:

1. Phase 8.1 implementation.
2. Phase 8.2 detection evolution.
3. Phase 8.3 threat intelligence.
