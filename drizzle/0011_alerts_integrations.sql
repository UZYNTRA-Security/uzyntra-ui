CREATE TABLE "alert_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"name" varchar(160) NOT NULL,
	"description" text,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"severity_threshold" varchar(32) DEFAULT 'high' NOT NULL,
	"confidence_threshold" real,
	"score_threshold" real,
	"detector_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"attack_types" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"anomaly_types" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"actions" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"route_patterns" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"aggregation_window_seconds" integer DEFAULT 300 NOT NULL,
	"threshold_count" integer DEFAULT 1 NOT NULL,
	"cooldown_seconds" integer DEFAULT 300 NOT NULL,
	"auto_create_incident" boolean DEFAULT false NOT NULL,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "alert_rules_status_chk" CHECK ("alert_rules"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "alert_rules_severity_chk" CHECK ("alert_rules"."severity_threshold" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "alert_rules_confidence_chk" CHECK ("alert_rules"."confidence_threshold" is null or "alert_rules"."confidence_threshold" between 0 and 1),
	CONSTRAINT "alert_rules_score_chk" CHECK ("alert_rules"."score_threshold" is null or "alert_rules"."score_threshold" between 0 and 100),
	CONSTRAINT "alert_rules_threshold_chk" CHECK ("alert_rules"."threshold_count" between 1 and 1000),
	CONSTRAINT "alert_rules_window_chk" CHECK ("alert_rules"."aggregation_window_seconds" between 30 and 86400),
	CONSTRAINT "alert_rules_cooldown_chk" CHECK ("alert_rules"."cooldown_seconds" between 0 and 86400)
);--> statement-breakpoint
CREATE TABLE "alert_suppressions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"alert_rule_id" uuid,
	"scope_type" varchar(32) NOT NULL,
	"scope_value" text,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"reason" text NOT NULL,
	"expires_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "alert_suppressions_status_chk" CHECK ("alert_suppressions"."status" in ('active', 'expired', 'deleted')),
	CONSTRAINT "alert_suppressions_scope_chk" CHECK ("alert_suppressions"."scope_type" in ('rule', 'detector', 'firewall', 'route', 'source_ip'))
);--> statement-breakpoint
CREATE TABLE "alerts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"alert_rule_id" uuid,
	"incident_id" uuid,
	"dedupe_fingerprint" varchar(64) NOT NULL,
	"status" varchar(32) DEFAULT 'open' NOT NULL,
	"severity" varchar(32) NOT NULL,
	"title" varchar(240) NOT NULL,
	"summary" text NOT NULL,
	"detector_id" varchar(80),
	"attack_type" varchar(80),
	"anomaly_type" varchar(80),
	"source_ip" varchar(45),
	"route" text,
	"event_count" integer DEFAULT 1 NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"last_notified_at" timestamp with time zone,
	"acknowledged_at" timestamp with time zone,
	"acknowledged_by_user_id" uuid,
	"resolved_at" timestamp with time zone,
	"resolved_by_user_id" uuid,
	"resolution_note" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "alerts_status_chk" CHECK ("alerts"."status" in ('open', 'acknowledged', 'resolved', 'suppressed')),
	CONSTRAINT "alerts_severity_chk" CHECK ("alerts"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "alerts_event_count_chk" CHECK ("alerts"."event_count" >= 1)
);--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"title" varchar(240) NOT NULL,
	"summary" text,
	"severity" varchar(32) NOT NULL,
	"status" varchar(32) DEFAULT 'open' NOT NULL,
	"assigned_to_user_id" uuid,
	"created_by_user_id" uuid,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"acknowledged_at" timestamp with time zone,
	"resolved_at" timestamp with time zone,
	"resolution" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incidents_status_chk" CHECK ("incidents"."status" in ('open', 'investigating', 'contained', 'resolved')),
	CONSTRAINT "incidents_severity_chk" CHECK ("incidents"."severity" in ('low', 'medium', 'high', 'critical'))
);--> statement-breakpoint
CREATE TABLE "incident_alerts" (
	"incident_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"linked_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_alerts_pk" PRIMARY KEY("incident_id","alert_id")
);--> statement-breakpoint
CREATE TABLE "notification_channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"type" varchar(32) NOT NULL,
	"name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"secret_reference" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"selected_events" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"created_by_user_id" uuid,
	"last_success_at" timestamp with time zone,
	"last_failure_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "notification_channels_status_chk" CHECK ("notification_channels"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "notification_channels_type_chk" CHECK ("notification_channels"."type" in ('webhook', 'email', 'siem'))
);--> statement-breakpoint
CREATE TABLE "notification_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"channel_id" uuid NOT NULL,
	"alert_id" uuid,
	"incident_id" uuid,
	"event_type" varchar(80) NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"response_status" integer,
	"last_error_code" varchar(80),
	"next_attempt_at" timestamp with time zone,
	"claimed_at" timestamp with time zone,
	"delivered_at" timestamp with time zone,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "notification_deliveries_status_chk" CHECK ("notification_deliveries"."status" in ('pending', 'claimed', 'delivered', 'retry', 'failed', 'blocked')),
	CONSTRAINT "notification_deliveries_attempts_chk" CHECK ("notification_deliveries"."attempt_count" >= 0 and "notification_deliveries"."max_attempts" between 1 and 10)
);--> statement-breakpoint
CREATE TABLE "scheduled_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"report_type" varchar(80) NOT NULL,
	"schedule" varchar(80) NOT NULL,
	"channel_id" uuid,
	"status" varchar(32) DEFAULT 'disabled' NOT NULL,
	"last_run_at" timestamp with time zone,
	"next_run_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "scheduled_reports_status_chk" CHECK ("scheduled_reports"."status" in ('active', 'disabled', 'deleted'))
);--> statement-breakpoint
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_suppressions" ADD CONSTRAINT "alert_suppressions_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_suppressions" ADD CONSTRAINT "alert_suppressions_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_suppressions" ADD CONSTRAINT "alert_suppressions_rule_fk" FOREIGN KEY ("alert_rule_id") REFERENCES "public"."alert_rules"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_suppressions" ADD CONSTRAINT "alert_suppressions_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_rule_fk" FOREIGN KEY ("alert_rule_id") REFERENCES "public"."alert_rules"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_ack_user_fk" FOREIGN KEY ("acknowledged_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_res_user_fk" FOREIGN KEY ("resolved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_assigned_user_fk" FOREIGN KEY ("assigned_to_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD CONSTRAINT "incident_alerts_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD CONSTRAINT "incident_alerts_alert_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD CONSTRAINT "incident_alerts_linked_by_fk" FOREIGN KEY ("linked_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_channels" ADD CONSTRAINT "notification_channels_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_channel_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_alert_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scheduled_reports" ADD CONSTRAINT "scheduled_reports_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scheduled_reports" ADD CONSTRAINT "scheduled_reports_channel_fk" FOREIGN KEY ("channel_id") REFERENCES "public"."notification_channels"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scheduled_reports" ADD CONSTRAINT "scheduled_reports_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "alert_rules_org_status_idx" ON "alert_rules" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "alert_rules_firewall_idx" ON "alert_rules" USING btree ("firewall_instance_id");--> statement-breakpoint
CREATE INDEX "alert_suppressions_org_status_idx" ON "alert_suppressions" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "alert_suppressions_scope_idx" ON "alert_suppressions" USING btree ("organization_id","scope_type");--> statement-breakpoint
CREATE UNIQUE INDEX "alerts_open_dedupe_idx" ON "alerts" USING btree ("organization_id","dedupe_fingerprint") WHERE status in ('open', 'acknowledged');--> statement-breakpoint
CREATE INDEX "alerts_org_status_time_idx" ON "alerts" USING btree ("organization_id","status","last_seen_at");--> statement-breakpoint
CREATE INDEX "alerts_firewall_time_idx" ON "alerts" USING btree ("firewall_instance_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "alerts_rule_time_idx" ON "alerts" USING btree ("alert_rule_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "incidents_org_status_time_idx" ON "incidents" USING btree ("organization_id","status","last_seen_at");--> statement-breakpoint
CREATE INDEX "incidents_firewall_time_idx" ON "incidents" USING btree ("firewall_instance_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "incident_alerts_alert_idx" ON "incident_alerts" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "notification_channels_org_status_idx" ON "notification_channels" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "notification_deliveries_pending_idx" ON "notification_deliveries" USING btree ("status","next_attempt_at");--> statement-breakpoint
CREATE INDEX "notification_deliveries_org_time_idx" ON "notification_deliveries" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "notification_deliveries_channel_idx" ON "notification_deliveries" USING btree ("channel_id","created_at");--> statement-breakpoint
CREATE INDEX "scheduled_reports_org_status_idx" ON "scheduled_reports" USING btree ("organization_id","status");--> statement-breakpoint
INSERT INTO "permissions" ("key", "description")
VALUES
  ('alerts.read', 'Read alerts and alert analytics'),
  ('alerts.manage', 'Manage alert rules and alert state'),
  ('incidents.read', 'Read security incidents'),
  ('incidents.manage', 'Manage security incident lifecycle'),
  ('integrations.manage', 'Manage notification and integration channels')
ON CONFLICT DO NOTHING;--> statement-breakpoint
WITH role_permission_keys ("role_name", "permission_key") AS (
  VALUES
    ('Owner', 'alerts.read'),
    ('Owner', 'alerts.manage'),
    ('Owner', 'incidents.read'),
    ('Owner', 'incidents.manage'),
    ('Owner', 'integrations.manage'),
    ('Security Admin', 'alerts.read'),
    ('Security Admin', 'alerts.manage'),
    ('Security Admin', 'incidents.read'),
    ('Security Admin', 'incidents.manage'),
    ('Security Admin', 'integrations.manage'),
    ('Analyst', 'alerts.read'),
    ('Analyst', 'incidents.read'),
    ('Analyst', 'incidents.manage'),
    ('Viewer', 'alerts.read')
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
