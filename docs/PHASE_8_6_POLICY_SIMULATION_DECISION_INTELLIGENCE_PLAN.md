# Phase 8.6 - Policy Simulation & Decision Intelligence Foundation Planning

Status: documentation only. Do not modify code, create migrations, deploy infrastructure, change secrets, commit, push, start implementation, or start Phase 8.7 in this phase.

Phase 8.6 designs the intelligence layer that safely connects detection decisions with adaptive enforcement. The goal is to make active protection explainable, testable, reversible, and enterprise-ready before real blocking becomes widespread.

Current capabilities:

- Security Operations Dashboard.
- Advanced Detection Engine.
- Threat Intelligence Layer.
- Zero Trust API Security.
- Adaptive API Protection Planning.
- Alerts.
- Incidents.
- Notification Deliveries.
- Risk Scoring.

Target workflow:

```text
Detect
  |
  v
Score
  |
  v
Explain
  |
  v
Simulate
  |
  v
Approve
  |
  v
Enforce
  |
  v
Measure
```

## 1. Policy Decision Architecture

### Decision Flow

```text
Request
 |
 v
Detection Signals
 |
 v
Threat Intelligence
 |
 v
Risk Engine
 |
 v
Policy Engine
 |
 v
Simulation Engine
 |
 v
Decision Explanation
 |
 v
Approval Workflow
 |
 v
Enforcement
```

### Responsibilities

| Layer | Responsibility |
| --- | --- |
| detection signals | collect detector, behavior, correlation, and threat intelligence evidence |
| risk engine | produce composite risk, confidence, severity, and reason codes |
| policy engine | evaluate tenant/firewall policy rules |
| simulation engine | compare would-enforce action against real action |
| explanation system | produce human and machine-readable decision reasons |
| approval workflow | control promotion from simulation to enforcement |
| enforcement | apply action only after policy mode and approval requirements are satisfied |

### Design Principles

- No enforcement without a policy decision record.
- No high-impact enforcement without explanation.
- No production blocking without observe/simulation history.
- No cross-tenant policy evaluation.
- No sensitive payload storage in decisions or replay data.
- Every lifecycle transition must be auditable.

## 2. Policy Simulation Engine

### Simulation Modes

| Mode | Purpose | Traffic Impact |
| --- | --- | --- |
| dry run | test policy against synthetic or selected examples | none |
| shadow evaluation | evaluate live traffic without enforcement | none |
| what-if analysis | adjust thresholds/rules and compare outcomes | none |
| historical replay | replay sanitized historical metadata | none |
| impact estimation | estimate affected requests, routes, identities, tenants | none |

### Simulation Output

Each simulation should produce:

- simulated action.
- actual action.
- risk score.
- confidence.
- matching policy rule.
- affected route/method.
- affected identity/source.
- reason codes.
- estimated false-positive risk.
- policy version.
- timestamp.

Example:

```json
{
  "policy_version": 12,
  "mode": "simulation",
  "actual_action": "ALLOW",
  "simulated_action": "BLOCK",
  "risk_score": 86,
  "confidence": 0.91,
  "reason_codes": [
    "sql_injection_high_confidence",
    "malicious_ip_reputation",
    "object_enumeration"
  ],
  "impact": {
    "requests": 42,
    "routes": 3,
    "identities": 2
  }
}
```

### Impact Estimation

Estimate:

- affected request count.
- affected tenants.
- affected APIs/routes.
- affected service accounts/API keys.
- expected alerts/incidents.
- potential customer disruption.
- estimated false positives.

For tenant users, impact must be tenant-local. Cross-tenant platform impact is internal-only and requires platform permission.

## 3. Decision Explanation System

### Human-Readable Explanations

Example:

```text
Decision: BLOCK

Reasons:
- SQL injection detector confidence 95%.
- Source matched malicious IP reputation indicator.
- Client showed abnormal object enumeration behavior.
- Policy threshold exceeded for sensitive endpoint.
```

Explanations should include:

- detector signal.
- threat intelligence context.
- behavior/correlation context.
- policy threshold.
- confidence.
- action reason.
- rollback or exception path where applicable.

### Machine-Readable Decision Objects

Decision object:

```json
{
  "decision_id": "decision_123",
  "request_id": "req_abc",
  "organization_id": "org_123",
  "firewall_instance_id": "fw_123",
  "policy_id": "policy_123",
  "policy_version": 5,
  "mode": "simulation",
  "recommended_action": "BLOCK",
  "enforced_action": "ALLOW",
  "risk_score": 82,
  "confidence": 0.88,
  "risk_band": "high",
  "reason_codes": ["malicious_ip", "endpoint_discovery"],
  "evidence": {
    "detectors": [],
    "threat_matches": [],
    "behavior": []
  }
}
```

### Audit Records

Audit:

- decision created.
- simulation run.
- policy approved.
- policy rejected.
- policy activated.
- rollback.
- override.
- emergency approval.

Audit metadata must exclude secrets and raw payloads.

## 4. Policy Testing Framework

### Policy Unit Testing

Policy authors should test:

- route matching.
- method matching.
- identity matching.
- risk threshold behavior.
- action selection.
- exception behavior.

### Regression Testing

Regression tests should verify:

- existing benign traffic remains allowed.
- known attack samples are challenged/rate-limited/blocked as expected.
- policy changes do not unexpectedly widen scope.
- rollback restores previous decision output.

### Attack Replay Testing

Replay:

- SQL injection events.
- object enumeration.
- credential stuffing.
- scanner behavior.
- malicious IP matches.
- sensitive endpoint abuse.

### Benign Traffic Testing

Replay:

- normal API usage.
- trusted service accounts.
- high-volume legitimate clients.
- expected admin operations.
- tenant-specific business flows.

### Validation Before Activation

Before activation:

- required tests pass.
- simulation impact reviewed.
- false-positive estimate acceptable.
- owner/reviewer approval completed.
- rollback version available.

## 5. Approval Workflow

### Approval Types

| Type | Use |
| --- | --- |
| automatic approval | low-risk observe/simulation policies |
| analyst approval | detector/risk threshold changes |
| security administrator approval | enforcement promotion or blocking rules |
| emergency approval | urgent containment during active incident |

### Approval Record

Fields:

- policy ID.
- policy version.
- requested action.
- requested by.
- reviewer.
- approval status.
- reason.
- expiration.
- created at.
- decided at.

### Rejection Reasons

Examples:

- excessive false-positive risk.
- unclear policy scope.
- insufficient simulation data.
- missing rollback plan.
- high customer impact.
- incomplete approval chain.

### Expiration

Approvals should expire:

- if policy changes.
- after a configured time.
- when simulation data becomes stale.
- after emergency window ends.

## 6. Change Management

### Policy Lifecycle

```text
Draft
  |
  v
Testing
  |
  v
Simulation
  |
  v
Approval
  |
  v
Active
  |
  v
Rollback
```

### Version History

Every policy change creates an immutable version:

- version number.
- diff.
- author.
- reviewer.
- status.
- mode.
- test results.
- simulation summary.
- rollback target.

### Diff View

Diff should show:

- route/method changes.
- threshold changes.
- action changes.
- exception changes.
- mode changes.
- approval requirement changes.

### Rollback

Rollback requirements:

- one-click rollback to previous active version.
- rollback audit event.
- reason required.
- optional incident link.
- gateway policy digest update.

### Policy Ownership

Each policy needs:

- owner.
- reviewer group.
- business context.
- protected APIs.
- operational contact.

## 7. Risk-Based Decision Engine

### Inputs

Combine:

- detection score.
- confidence.
- threat intelligence.
- tenant sensitivity.
- endpoint sensitivity.
- user identity risk.
- behavior history.
- policy mode.
- exception state.

### Risk Bands

| Band | Score | Meaning | Default Action |
| --- | --- | --- | --- |
| low | 0-29 | normal or weak signal | allow |
| medium | 30-49 | suspicious but uncertain | observe/challenge |
| high | 50-74 | likely malicious or abusive | challenge/rate limit |
| critical | 75-100 | strong malicious evidence | block/quarantine in approved enforcement |

### Risk Decision Rules

Rules must consider:

- confidence floor.
- tenant mode.
- endpoint sensitivity.
- allowlists.
- false-positive history.
- current incident state.

Critical risk should not automatically block unless:

- enforcement mode is active.
- policy is approved.
- no exception applies.
- fail-mode allows it.

## 8. Historical Replay System

### Replay Inputs

Replay should use sanitized metadata:

- timestamp.
- route template.
- method.
- status code.
- detector IDs.
- score/confidence.
- source fingerprint.
- identity fingerprint.
- threat indicator match IDs.
- action taken.

Do not store or replay:

- request body.
- authorization headers.
- cookies.
- raw tokens.
- passwords.
- private keys.

### Replay Uses

- test new policies.
- compare old vs new thresholds.
- estimate blocking impact.
- tune false-positive controls.
- generate customer-ready policy reports.

### Tenant Isolation

- tenant replay jobs can only use tenant data.
- cross-tenant internal replay requires platform permission.
- replay output must not expose other tenant identifiers.

### Replay Output

- total evaluated requests.
- simulated actions.
- affected routes.
- affected identities.
- false-positive estimate.
- top reason codes.
- policy recommendations.

## 9. Security Operations Integration

### Alerts

Create alerts for:

- simulation predicts high-impact block.
- policy failure.
- repeated would-block decisions.
- approval expiration.
- emergency approval.

### Incidents

Link decisions to incidents when:

- policy is activated during incident response.
- quarantine is recommended.
- credential suspension is recommended.
- repeated critical decisions affect sensitive APIs.

### Notification Deliveries

Notify on:

- enforcement promotion.
- rollback.
- emergency approval.
- critical simulation finding.
- approval request nearing expiration.

### Analyst Feedback

Feedback should adjust:

- false-positive estimates.
- detector tuning.
- threat indicator review.
- policy threshold recommendations.

### Audit Logs

Audit:

- simulation jobs.
- test results.
- approvals.
- rejections.
- activations.
- rollbacks.
- overrides.

## 10. UI Planning

### `/policy-simulator`

Purpose:

- run dry-run, what-if, and historical replay tests.

Components:

- policy selector.
- input sample selector.
- threshold editor.
- simulated decision output.
- false-positive estimate.
- affected route/identity summary.

### `/policy-decisions`

Purpose:

- investigate decision history.

Components:

- decision timeline.
- mode/action filter.
- risk band filter.
- policy version filter.
- reason-code explanation.
- actual vs simulated action comparison.

### `/policy-history`

Purpose:

- track policy lifecycle and changes.

Components:

- version list.
- diff view.
- test status.
- simulation summary.
- approval status.
- rollback button.

### `/approval-workflows`

Purpose:

- manage policy approvals.

Components:

- approval queue.
- reviewer.
- requested action.
- simulation impact.
- approve/reject controls.
- expiration.

## 11. Enterprise Features

### Multi-Tenant Policy Inheritance

Support:

- platform defaults.
- organization policies.
- firewall overrides.
- route exceptions.

Inheritance order:

```text
platform default
  |
  v
organization policy
  |
  v
firewall policy
  |
  v
route/identity exception
```

Tenant data remains isolated even when policy templates are shared.

### Exceptions

Exceptions require:

- scope.
- owner.
- reason.
- expiration.
- audit record.
- affected policy version.

### Emergency Break-Glass

Break-glass:

- short-lived.
- reason required.
- MFA later.
- notification-backed.
- reviewed after use.

### Compliance Reporting

Reports:

- policy approvals.
- decision explanations.
- simulation history.
- rollback history.
- emergency approvals.
- test coverage.

## 12. Performance Requirements

### Decision Latency Targets

Target:

- policy decision p50 under 2 ms.
- p95 under 10 ms.
- p99 under 25 ms.

Simulation and replay can be asynchronous.

### Caching

Cache:

- compiled policy versions.
- route selectors.
- exception sets.
- approval state.
- simulation summaries.

Cache invalidation:

- policy version change.
- approval decision.
- exception update.
- rollback.
- emergency bypass.

### Asynchronous Analysis

Async jobs:

- historical replay.
- impact estimation.
- false-positive calculation.
- policy regression testing.
- report generation.

### High-Volume Replay

Requirements:

- pagination.
- bounded batches.
- resumable jobs.
- progress tracking.
- tenant-scoped workers.
- sanitized inputs only.

## 13. Compliance Alignment

### NIST Zero Trust

| Concept | UZYNTRA Mapping |
| --- | --- |
| policy decision point | policy engine and simulator |
| policy enforcement point | adaptive protection engine / gateway |
| continuous evaluation | risk and decision lifecycle |
| enterprise policy | versioned policies and approvals |
| telemetry | decisions, simulations, alerts, incidents |

### NIST CSF

| Function | Phase 8.6 Contribution |
| --- | --- |
| Identify | policy impact and protected API inventory |
| Protect | safer enforcement activation |
| Detect | would-block decisions and simulation outcomes |
| Respond | approval, rollback, emergency workflows |
| Recover | policy rollback and post-incident hardening |

### OWASP API Security Top 10

Policy simulation helps safely test controls for:

- broken object level authorization.
- broken authentication.
- unrestricted resource consumption.
- broken function level authorization.
- sensitive business flow abuse.
- improper inventory management.

### SOC 2 Change Management

Evidence:

- policy versions.
- test results.
- approvals.
- rejections.
- simulations.
- activation records.
- rollback history.
- emergency access records.

## Implementation Sequence Recommendation

Recommended Phase 8.6 implementation slices:

1. Policy decision object and explanation format.
2. Policy simulation APIs.
3. Historical replay job model.
4. Approval workflow model.
5. UI pages for simulator, decisions, history, approvals.
6. Audit integration.
7. False-positive and impact estimation.
8. Gateway-safe decision export format.

## Release Gate Proposal

Phase 8.6 implementation should be ready only when:

- simulation produces deterministic decisions.
- explanations are human and machine-readable.
- replay uses sanitized metadata only.
- approvals are auditable.
- rollback path is tested.
- no enforcement happens without explicit active policy mode.
- tenant isolation is validated.
- performance targets are measured.
- Phase 5, 6, 8.1, 8.2, 8.3, 8.4, and 8.5 tests still pass.

## Phase 8.6 Status

PHASE 8.6 PLANNING STATUS: READY

This document defines the Policy Simulation and Decision Intelligence Foundation plan only. No code was modified, no migrations were created, no infrastructure was deployed, no secrets were changed, no commits or pushes were made, implementation was not started, and Phase 8.7 was not started.

Recommended next sequence:

1. Phase 8.6 implementation.
2. Phase 8.7 automated response and remediation planning.
3. Enterprise readiness review before production enforcement.
