INSERT INTO "permissions" ("key", "description")
VALUES
  ('events.read', 'Read security events'),
  ('events.export', 'Export security events'),
  ('metrics.read', 'Read security metrics'),
  ('audits.read', 'Read audit entries'),
  ('mitigation.read', 'Read active mitigations'),
  ('mitigation.create', 'Create mitigations'),
  ('mitigation.delete', 'Remove mitigations'),
  ('reputation.read', 'Read source reputation'),
  ('reputation.reset', 'Reset source reputation'),
  ('policy.read', 'Read firewall policy'),
  ('policy.update', 'Update firewall policy'),
  ('users.manage', 'Manage organization users'),
  ('roles.manage', 'Manage organization roles'),
  ('api_keys.manage', 'Manage API keys'),
  ('service_accounts.manage', 'Manage service accounts'),
  ('billing.manage', 'Manage billing settings'),
  ('firewalls.manage', 'Manage firewall instances')
ON CONFLICT DO NOTHING;
--> statement-breakpoint
INSERT INTO "roles" ("organization_id", "name", "description")
VALUES
  (NULL, 'Owner', 'Full organization control'),
  (NULL, 'Security Admin', 'Manage security operations and policy'),
  (NULL, 'Analyst', 'Investigate activity and review reputation'),
  (NULL, 'Viewer', 'Read basic security telemetry')
ON CONFLICT DO NOTHING;
--> statement-breakpoint
WITH role_permission_keys ("role_name", "permission_key") AS (
  VALUES
    ('Owner', 'events.read'),
    ('Owner', 'events.export'),
    ('Owner', 'metrics.read'),
    ('Owner', 'audits.read'),
    ('Owner', 'mitigation.read'),
    ('Owner', 'mitigation.create'),
    ('Owner', 'mitigation.delete'),
    ('Owner', 'reputation.read'),
    ('Owner', 'reputation.reset'),
    ('Owner', 'policy.read'),
    ('Owner', 'policy.update'),
    ('Owner', 'users.manage'),
    ('Owner', 'roles.manage'),
    ('Owner', 'api_keys.manage'),
    ('Owner', 'service_accounts.manage'),
    ('Owner', 'billing.manage'),
    ('Owner', 'firewalls.manage'),
    ('Security Admin', 'events.read'),
    ('Security Admin', 'events.export'),
    ('Security Admin', 'metrics.read'),
    ('Security Admin', 'audits.read'),
    ('Security Admin', 'mitigation.read'),
    ('Security Admin', 'mitigation.create'),
    ('Security Admin', 'mitigation.delete'),
    ('Security Admin', 'reputation.read'),
    ('Security Admin', 'reputation.reset'),
    ('Security Admin', 'policy.read'),
    ('Security Admin', 'policy.update'),
    ('Analyst', 'events.read'),
    ('Analyst', 'metrics.read'),
    ('Analyst', 'audits.read'),
    ('Analyst', 'reputation.read'),
    ('Viewer', 'events.read'),
    ('Viewer', 'metrics.read')
)
INSERT INTO "role_permissions" ("role_id", "permission_id")
SELECT "roles"."id", "permissions"."id"
FROM role_permission_keys
INNER JOIN "roles"
  ON "roles"."name" = role_permission_keys."role_name"
  AND "roles"."organization_id" IS NULL
INNER JOIN "permissions"
  ON "permissions"."key" = role_permission_keys."permission_key"
ON CONFLICT DO NOTHING;
