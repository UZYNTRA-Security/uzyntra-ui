# Phase 8.3 - Threat Intelligence Layer Planning

Status: documentation only. Do not modify code, create migrations, deploy infrastructure, add external providers, change secrets, commit, push, or start implementation in this phase.

Phase 8.3 designs the intelligence pipeline that will enrich the Phase 8.2 deterministic detection engine with external and curated threat context.

Current stack:

```text
API Traffic
    |
    v
Phase 5 Detection Engine
    |
    v
Phase 8.2 Advanced Detection
    |
    +--> behavioral analysis
    +--> correlation engine
    +--> composite risk scoring
    +--> detector intelligence
    +--> analyst feedback
    |
    v
Phase 6 Alerts / Incidents
    |
    v
Phase 8.1 Security Operations
```

Phase 8.3 target:

```text
External Intelligence
        |
        v
Threat Intelligence Layer
        |
        +--> IP reputation
        +--> ASN context
        +--> malware / scanner indicators
        +--> geo risk
        +--> threat campaigns
        |
        v
Detection Risk Engine
        |
        v
Alerts / Incidents
```

## 1. Threat Intelligence Architecture

### Flow

```text
External intelligence sources
        |
        v
provider adapters
        |
        v
normalization and validation
        |
        v
threat intelligence engine
        |
        +--> reputation cache
        +--> indicator store
        +--> match history
        +--> source health
        |
        v
detection enrichment
        |
        v
risk scoring
```

### Responsibilities

| Layer | Responsibility |
| --- | --- |
| provider adapters | fetch indicators from external or curated sources |
| normalization | convert provider-specific payloads into UZYNTRA indicator records |
| validation | reject malformed, stale, low-confidence, or unsafe indicators |
| cache | serve low-latency lookup results for request-time enrichment |
| indicator store | retain validated indicators and source attribution |
| match engine | record when telemetry matches an indicator |
| enrichment | attach safe threat context to detections |
| operations UI | show source health, matches, false positives, and campaign context |

Phase 8.3 should not block gateway request processing on slow provider calls. Request-time detection should use cached/local intelligence only.

## 2. Intelligence Categories

### IP Reputation

Planned support:

- malicious IPs.
- scanners.
- botnet nodes.
- brute-force sources.
- abusive cloud hosts.
- known exploit infrastructure.

Fields:

- IP or CIDR.
- reputation score.
- confidence.
- category.
- source.
- first seen / last seen.
- expiration.

Usage:

- increase event risk.
- improve confidence for scanner/abuse detections.
- correlate repeated tenant targeting by source.
- prioritize alerts from known malicious infrastructure.

### Network Intelligence

Planned support:

- ASN reputation.
- hosting provider classification.
- VPN/proxy/TOR indicators.
- residential vs data-center context.
- bulletproof hosting tags where available.

Risk impact examples:

| Signal | Risk impact |
| --- | --- |
| known scanner ASN | moderate increase |
| TOR exit node | contextual increase, not automatically malicious |
| bulletproof hosting | high increase |
| trusted corporate ASN | possible score reduction if tenant-configured |

### Geolocation Intelligence

Planned support:

- country risk.
- impossible travel context.
- abnormal tenant access regions.
- new-region source for sensitive endpoints.

Rules:

- use coarse country/region only.
- avoid storing precise location.
- treat geo as contextual, not decisive.
- tenant-specific geography baselines must remain tenant-local.

### User-Agent Intelligence

Planned support:

- scanners.
- automation tools.
- suspicious clients.
- outdated libraries.
- known exploit tools.
- spoofed or missing user agents.

Examples:

- `sqlmap`, `nuclei`, `nikto`, `masscan`, `zgrab`.
- scripted clients such as `python-requests`, `curl`, `Go-http-client`.
- suspicious browser mismatch patterns.

### Threat Indicators

Planned indicators:

- IP addresses.
- CIDR ranges.
- domains.
- URLs.
- hashes.
- user-agent signatures.
- scanner signatures.
- campaign IDs.

Do not store customer request bodies as indicators. Only store normalized, bounded, security-safe indicator values.

## 3. Provider Abstraction Layer

### Provider Interface

Future provider adapters should implement:

```text
provider.id
provider.displayName
provider.capabilities
provider.fetchIndicators(cursor)
provider.lookup(value, type)
provider.health()
provider.normalize(rawIndicator)
```

Provider capabilities:

- `ip_reputation`
- `asn_context`
- `domain_reputation`
- `url_reputation`
- `hash_reputation`
- `scanner_signatures`
- `campaign_context`

### Multiple Intelligence Sources

The engine must support:

- internal curated indicators.
- open-source feeds.
- commercial providers.
- customer-managed allow/block indicators.
- future STIX/TAXII feeds.

Provider results should not overwrite each other blindly. The engine should preserve attribution and compute a merged reputation view.

### Caching Strategy

| Cache | Purpose | TTL |
| --- | --- | --- |
| hot lookup cache | request-time enrichment | 5-30 minutes |
| reputation cache | normalized provider result | provider TTL or 24 hours |
| negative cache | avoid repeated misses | 5-15 minutes |
| source health cache | provider status | 1-5 minutes |

Cache keys must include indicator type and normalized value. Tenant-specific indicators must include `organization_id`.

### Rate Limiting

Provider calls must be rate limited by:

- provider.
- organization where tenant-owned feeds exist.
- lookup type.
- sync job.

Provider rate limit exhaustion must degrade gracefully:

- use cached data.
- mark provider stale.
- avoid blocking detection.
- emit source health event.

### Provider Failure Handling

Failure states:

- timeout.
- authentication failure.
- rate limit.
- malformed response.
- stale feed.
- source disabled.

Failure handling:

- keep last known good data until expiration.
- mark source health degraded.
- audit configuration failures.
- do not lower risk just because a provider is unavailable.

No external providers are integrated in this planning phase.

## 4. Threat Intelligence Database Design

No migrations in Phase 8.3 planning. The following models are proposals only.

### `indicator_sources`

Purpose:

- Track configured intelligence sources and health.

Suggested fields:

- `id`
- `organization_id` nullable for global/platform sources.
- `name`
- `provider_type`
- `status`
- `capabilities`
- `configuration`
- `secret_reference`
- `last_sync_at`
- `last_success_at`
- `last_failure_at`
- `last_failure_code`
- `health_status`
- `created_by_user_id`
- timestamps / deleted timestamp.

Indexes:

- `(organization_id, status)`
- `(provider_type, status)`
- `(health_status, last_sync_at)`

Security:

- store secrets only by reference.
- audit every create/update/delete/rotate.

### `threat_indicators`

Purpose:

- Store normalized indicators.

Suggested fields:

- `id`
- `organization_id` nullable for platform/global indicators.
- `source_id`
- `indicator_type`
- `indicator_value_hash`
- `indicator_value_display`
- `category`
- `reputation_score`
- `confidence`
- `severity`
- `tags`
- `first_seen_at`
- `last_seen_at`
- `expires_at`
- `source_metadata`
- timestamps.

Indexes:

- `(indicator_type, indicator_value_hash)`
- `(organization_id, indicator_type, indicator_value_hash)`
- `(source_id, last_seen_at)`
- `(expires_at)`
- `(category, reputation_score)`

Tenant isolation:

- global indicators can enrich all tenants.
- tenant-owned indicators must never enrich another tenant.
- queries must prefer tenant-specific indicator over global fallback when both match.

Retention:

- expire indicators by provider TTL.
- keep match history longer than raw indicators if needed for incident evidence.

### `indicator_matches`

Purpose:

- Record telemetry matches against indicators.

Suggested fields:

- `id`
- `organization_id`
- `firewall_instance_id`
- `security_event_id`
- `indicator_id`
- `indicator_type`
- `match_value_hash`
- `match_context`
- `risk_delta`
- `confidence_delta`
- `matched_at`

Indexes:

- `(organization_id, matched_at)`
- `(firewall_instance_id, matched_at)`
- `(security_event_id)`
- `(indicator_id, matched_at)`

Security:

- store hashes and safe labels.
- do not store request headers, cookies, credentials, or payload secrets.

### `reputation_cache`

Purpose:

- Low-latency merged reputation lookup.

Suggested fields:

- `id`
- `organization_id` nullable.
- `indicator_type`
- `lookup_hash`
- `lookup_label`
- `reputation_score`
- `confidence`
- `categories`
- `source_ids`
- `expires_at`
- `last_refreshed_at`
- `payload`

Indexes:

- `(organization_id, indicator_type, lookup_hash)`
- `(indicator_type, lookup_hash)`
- `(expires_at)`

### `threat_feeds`

Purpose:

- Track feed sync state and cursors.

Suggested fields:

- `id`
- `source_id`
- `feed_name`
- `sync_cursor`
- `sync_status`
- `last_started_at`
- `last_completed_at`
- `last_error_code`
- `items_processed`
- `items_rejected`
- `items_expired`

Indexes:

- `(source_id, sync_status)`
- `(last_completed_at)`

## 5. Detection Integration

Threat intelligence should affect:

- event scoring.
- confidence.
- severity.
- correlation.
- alert priority.
- incident grouping.

### Risk Formula Impact

Phase 8.2 formula:

```text
event risk
+ client risk
+ API risk
+ tenant risk
= composite risk
```

Phase 8.3 adds:

```text
event risk
+ client risk
+ API risk
+ tenant risk
+ threat intelligence risk
= enriched composite risk
```

Example:

```text
normal request score       20
known malicious IP        +40
known scanner ASN         +20
scanner user-agent        +15
tenant allowlist          -20
final score                75
severity                   high
```

### Confidence Impact

Threat intelligence should increase confidence only when:

- source is trusted.
- indicator is fresh.
- provider confidence is above threshold.
- multiple sources corroborate the signal.

Stale or low-confidence indicators should add context, not severity.

### Correlation Impact

Threat intelligence can group:

- same source across many endpoints.
- same ASN campaign against many tenants.
- same scanner signature across time windows.
- same domain/URL/hash across multiple events.

Cross-tenant campaign views must require explicit internal platform permission and must not expose tenant data to other tenants.

### Alert Priority Impact

Alerts should gain priority when:

- critical event plus malicious reputation.
- medium event plus high-confidence campaign indicator.
- repeated findings from same malicious infrastructure.
- detector confidence and external intelligence agree.

Alerts should not auto-escalate solely because a country is considered risky.

## 6. Intelligence Operations

### Feed Synchronization

Sync flow:

```text
scheduled job
  |
  v
provider adapter
  |
  v
normalize
  |
  v
validate
  |
  v
upsert indicators
  |
  v
refresh reputation cache
  |
  v
record source health
```

Sync requirements:

- bounded batch size.
- resumable cursor.
- provider-specific rate limits.
- item rejection counts.
- failure audit trail.
- no secret values in logs.

### Indicator Expiration

Every indicator must have one of:

- explicit provider expiration.
- default TTL.
- analyst-owned expiration.

Expired indicators:

- should not enrich new events.
- may remain visible in historical matches.
- should be purged or archived by retention policy.

### Stale Data Handling

Stale source behavior:

- mark source degraded.
- continue using unexpired cache.
- lower confidence for stale-but-not-expired indicators.
- never treat provider unavailability as proof that a source is safe.

### False Positive Handling

Support:

- indicator allowlist.
- source-specific suppression.
- tenant-specific exceptions.
- analyst feedback.
- expiration timestamp.
- audit history.

False positive feedback should affect:

- local tenant score adjustments.
- source trust score.
- future provider selection.
- detector confidence where relevant.

### Analyst Review Workflow

```text
indicator match
  |
  v
analyst reviews event and source attribution
  |
  +--> confirmed malicious
  |      v
  |    retain / escalate / create incident
  |
  +--> false positive
  |      v
  |    create exception / lower source trust / audit
  |
  +--> unknown
         v
       observe / request more context
```

## 7. UI Design

### `/threat-intelligence`

Purpose:

- SOC overview of threat intelligence value and current malicious infrastructure.

Widgets:

- total active indicators.
- matches in last 24 hours.
- top malicious IPs.
- top ASNs.
- campaign timeline.
- enriched risk delta.
- source health summary.

Charts:

- malicious IP timeline.
- indicator matches by category.
- source confidence distribution.
- geo risk map/table.

### `/intelligence-sources`

Purpose:

- manage and monitor intelligence sources.

Components:

- source list.
- provider type.
- capabilities.
- status.
- last sync.
- last failure.
- health score.
- sync statistics.

Future actions:

- enable/disable source.
- rotate secret reference.
- test connection.
- trigger sync.

All actions require integration/security admin permission and audit logging.

### `/threat-indicators`

Purpose:

- search, review, and triage indicators.

Components:

- indicator table.
- type/category filters.
- source filter.
- confidence/risk filter.
- expiration view.
- match count.
- false positive/exception controls.

### Supporting Views

Add threat context panels to:

- detections.
- risk analysis.
- correlation events.
- alerts.
- incidents.

Panels should show safe attribution:

- source name.
- indicator type.
- category.
- confidence.
- freshness.
- risk delta.

Do not show raw secrets, private provider payloads, or unsafe request data.

## 8. Security Requirements

### No Customer Data Leakage

- Do not send customer request payloads to external providers.
- Do not send tenant identifiers to third-party reputation lookups unless explicitly approved.
- Prefer local cache lookups.
- Hash or normalize lookup values where provider supports it.

### Tenant Isolation

- Tenant indicators remain tenant-scoped.
- Match history is organization-scoped.
- Cross-tenant campaign analytics require internal platform permission.
- Cache keys must include tenant scope where applicable.

### Indicator Poisoning Protection

Risks:

- malicious feed inserts false indicators.
- compromised source pushes broad CIDRs.
- low-quality feed creates alert noise.

Controls:

- source trust score.
- maximum risk delta by provider.
- indicator validation.
- CIDR size limits.
- expiration requirements.
- human review for high-impact indicators.
- staged observe-only mode for new sources.

### Malicious Feed Protection

Feed ingestion must:

- validate content type and size.
- reject oversized payloads.
- reject unsupported indicator types.
- sanitize strings.
- limit nested metadata.
- avoid executing provider content.
- isolate provider failures.

### Audit Logging

Audit:

- source creation/update/delete.
- source credential rotation.
- feed sync failures.
- manual indicator creation.
- indicator exception/allowlist.
- false-positive feedback.
- source disablement.

Audit metadata must not contain provider secrets or raw feed credentials.

## 9. Performance Architecture

### Lookup Latency

Request path rule:

```text
request-time lookup = local cache only
external provider lookup = async only
```

Latency budget:

- in-memory cache lookup: sub-millisecond target.
- local database cache lookup: low milliseconds.
- no synchronous provider calls in the gateway hot path.

### High-Volume Matching

Use layered matching:

1. in-memory hot cache for common IP/ASN/user-agent lookups.
2. local reputation cache table.
3. async enrichment worker for missed or expensive lookups.
4. background feed sync.

### Caching

Cache by:

- indicator type.
- normalized value hash.
- organization scope.
- provider/source set.

Cache invalidation:

- expiration.
- source disablement.
- manual exception.
- indicator update.
- emergency purge.

### Async Updates

Async workers:

- sync feeds.
- expire indicators.
- recompute merged reputation.
- enrich recent events where cache was missing.
- update source health.

Workers must be idempotent and resumable.

### Storage Controls

- bound provider metadata size.
- truncate labels.
- hash sensitive lookup values.
- cap match history retention.
- archive or delete expired stale indicators.

## 10. Enterprise Alignment

### MITRE ATT&CK

Map indicators and matches to ATT&CK where appropriate:

| Concept | UZYNTRA Use |
| --- | --- |
| Reconnaissance | endpoint discovery, scanner IPs, probing infrastructure |
| Initial Access | credential attacks, exploit attempts, malicious sources |
| Credential Access | token replay and brute-force indicators |
| Discovery | API route enumeration and scanner campaigns |
| Command and Control | malicious domains/URLs where API callbacks are detected |

### STIX/TAXII Concepts

UZYNTRA concepts should align with:

- indicator.
- observed data.
- relationship.
- sighting.
- identity/source.
- marking/handling metadata.

Do not require full STIX/TAXII implementation in the first version. Design models so future import/export is possible.

### NIST CSF

| Function | Threat Intel Contribution |
| --- | --- |
| Identify | known threat sources and exposed API risks |
| Protect | block/allow policies based on vetted indicators |
| Detect | enriched detection and campaign correlation |
| Respond | prioritized incidents with source attribution |
| Recover | post-incident evidence and trend review |

### SOC Workflows

Threat intelligence should support:

- triage prioritization.
- incident enrichment.
- source attribution.
- campaign tracking.
- false-positive management.
- source health monitoring.
- executive reporting.

## Implementation Sequence Recommendation

Recommended Phase 8.3 implementation slices:

1. Threat intelligence model and provider interface.
2. Local curated indicator support.
3. Reputation cache and local lookup service.
4. Detection enrichment integration with Phase 8.2 scoring.
5. Indicator match recording.
6. Source health and feed sync foundation.
7. Threat intelligence UI pages.
8. False-positive and exception workflow.
9. Optional external provider adapters after local pipeline is proven.

## Release Gate Proposal

Phase 8.3 implementation should be ready only when:

- local indicators enrich detections without external provider dependency.
- request-time lookups use local cache only.
- no customer payloads are sent to external providers.
- tenant indicators do not leak across organizations.
- provider/source failures degrade safely.
- stale indicators are handled correctly.
- source health is visible.
- indicator matches are auditable.
- Phase 5, 6, 8.1, and 8.2 tests still pass.

## Phase 8.3 Status

PHASE 8.3 PLANNING STATUS: READY

This document defines the Threat Intelligence Layer plan only. No code was modified, no migrations were created, no infrastructure was deployed, no external providers were added, no secrets were changed, no commits or pushes were made, implementation was not started, and Phase 8.4 was not started.

Recommended next sequence:

1. Phase 8.3 implementation.
2. Phase 8.4 zero trust API security.
3. Phase 8.5 compliance and evidence dashboard.
