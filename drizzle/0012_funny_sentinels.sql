CREATE TABLE "behavioral_baselines" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"baseline_type" varchar(64) NOT NULL,
	"baseline_key_hash" varchar(64) NOT NULL,
	"baseline_key_label" varchar(160),
	"window_seconds" integer DEFAULT 86400 NOT NULL,
	"sample_count" integer DEFAULT 0 NOT NULL,
	"request_rate_per_minute" real DEFAULT 0 NOT NULL,
	"method_mix" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"route_frequency" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"client_fingerprint" varchar(64),
	"learned_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "behavioral_baselines_window_chk" CHECK ("behavioral_baselines"."window_seconds" between 60 and 2592000),
	CONSTRAINT "behavioral_baselines_sample_count_chk" CHECK ("behavioral_baselines"."sample_count" >= 0)
);
--> statement-breakpoint
CREATE TABLE "correlation_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"correlation_type" varchar(80) NOT NULL,
	"severity" varchar(32) NOT NULL,
	"confidence" real NOT NULL,
	"risk_score" real NOT NULL,
	"related_event_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"related_detector_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"identity_fingerprint" varchar(64),
	"route_fingerprint" varchar(64),
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" varchar(32) DEFAULT 'open' NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"dedupe_fingerprint" varchar(64) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "correlation_events_severity_chk" CHECK ("correlation_events"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "correlation_events_status_chk" CHECK ("correlation_events"."status" in ('open', 'acknowledged', 'suppressed', 'resolved')),
	CONSTRAINT "correlation_events_confidence_chk" CHECK ("correlation_events"."confidence" between 0 and 1),
	CONSTRAINT "correlation_events_risk_score_chk" CHECK ("correlation_events"."risk_score" between 0 and 100)
);
--> statement-breakpoint
CREATE TABLE "detection_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"security_event_id" uuid,
	"finding_type" varchar(80) NOT NULL,
	"detector_id" varchar(80) NOT NULL,
	"severity" varchar(32) NOT NULL,
	"confidence" real NOT NULL,
	"risk_score" real NOT NULL,
	"composite_risk" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" varchar(32) DEFAULT 'open' NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"event_count" integer DEFAULT 1 NOT NULL,
	"dedupe_fingerprint" varchar(64) NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "detection_findings_severity_chk" CHECK ("detection_findings"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "detection_findings_status_chk" CHECK ("detection_findings"."status" in ('open', 'acknowledged', 'suppressed', 'resolved')),
	CONSTRAINT "detection_findings_confidence_chk" CHECK ("detection_findings"."confidence" between 0 and 1),
	CONSTRAINT "detection_findings_risk_score_chk" CHECK ("detection_findings"."risk_score" between 0 and 100),
	CONSTRAINT "detection_findings_event_count_chk" CHECK ("detection_findings"."event_count" >= 1)
);
--> statement-breakpoint
CREATE TABLE "detector_configurations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"detector_id" varchar(80) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"confidence_threshold" real DEFAULT 0.5 NOT NULL,
	"severity_override" varchar(32),
	"tuning" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"suppression_rules" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "detector_configurations_status_chk" CHECK ("detector_configurations"."status" in ('active', 'observe', 'disabled', 'deleted')),
	CONSTRAINT "detector_configurations_severity_chk" CHECK ("detector_configurations"."severity_override" is null or "detector_configurations"."severity_override" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "detector_configurations_confidence_chk" CHECK ("detector_configurations"."confidence_threshold" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "detector_feedback" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"detector_id" varchar(80) NOT NULL,
	"security_event_id" uuid,
	"finding_id" uuid,
	"feedback_type" varchar(64) NOT NULL,
	"note" text,
	"created_by_user_id" uuid,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "detector_feedback_type_chk" CHECK ("detector_feedback"."feedback_type" in ('true_positive', 'false_positive', 'expected_behavior', 'duplicate', 'needs_tuning', 'customer_exception'))
);
--> statement-breakpoint
ALTER TABLE "behavioral_baselines" ADD CONSTRAINT "behavioral_baselines_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "behavioral_baselines" ADD CONSTRAINT "behavioral_baselines_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_events" ADD CONSTRAINT "correlation_events_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "correlation_events" ADD CONSTRAINT "correlation_events_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_findings" ADD CONSTRAINT "detection_findings_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_findings" ADD CONSTRAINT "detection_findings_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detection_findings" ADD CONSTRAINT "detection_findings_security_event_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_configurations" ADD CONSTRAINT "detector_configurations_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_configurations" ADD CONSTRAINT "detector_configurations_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_configurations" ADD CONSTRAINT "detector_configurations_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_feedback" ADD CONSTRAINT "detector_feedback_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_feedback" ADD CONSTRAINT "detector_feedback_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_feedback" ADD CONSTRAINT "detector_feedback_security_event_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_feedback" ADD CONSTRAINT "detector_feedback_finding_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."detection_findings"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "detector_feedback" ADD CONSTRAINT "detector_feedback_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "behavioral_baselines_unique_idx" ON "behavioral_baselines" USING btree ("organization_id","firewall_instance_id","baseline_type","baseline_key_hash");--> statement-breakpoint
CREATE INDEX "behavioral_baselines_org_type_idx" ON "behavioral_baselines" USING btree ("organization_id","baseline_type");--> statement-breakpoint
CREATE INDEX "behavioral_baselines_firewall_learned_idx" ON "behavioral_baselines" USING btree ("firewall_instance_id","learned_at");--> statement-breakpoint
CREATE INDEX "correlation_events_org_status_time_idx" ON "correlation_events" USING btree ("organization_id","status","window_end");--> statement-breakpoint
CREATE INDEX "correlation_events_firewall_time_idx" ON "correlation_events" USING btree ("firewall_instance_id","window_end");--> statement-breakpoint
CREATE INDEX "correlation_events_type_idx" ON "correlation_events" USING btree ("organization_id","correlation_type");--> statement-breakpoint
CREATE INDEX "correlation_events_dedupe_idx" ON "correlation_events" USING btree ("organization_id","dedupe_fingerprint");--> statement-breakpoint
CREATE INDEX "detection_findings_org_status_time_idx" ON "detection_findings" USING btree ("organization_id","status","last_seen_at");--> statement-breakpoint
CREATE INDEX "detection_findings_firewall_time_idx" ON "detection_findings" USING btree ("firewall_instance_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "detection_findings_detector_idx" ON "detection_findings" USING btree ("organization_id","detector_id");--> statement-breakpoint
CREATE INDEX "detection_findings_dedupe_idx" ON "detection_findings" USING btree ("organization_id","dedupe_fingerprint");--> statement-breakpoint
CREATE UNIQUE INDEX "detector_configurations_unique_idx" ON "detector_configurations" USING btree ("organization_id","firewall_instance_id","detector_id");--> statement-breakpoint
CREATE INDEX "detector_configurations_org_status_idx" ON "detector_configurations" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "detector_configurations_firewall_idx" ON "detector_configurations" USING btree ("firewall_instance_id");--> statement-breakpoint
CREATE INDEX "detector_feedback_org_detector_idx" ON "detector_feedback" USING btree ("organization_id","detector_id");--> statement-breakpoint
CREATE INDEX "detector_feedback_firewall_idx" ON "detector_feedback" USING btree ("firewall_instance_id");--> statement-breakpoint
CREATE INDEX "detector_feedback_event_idx" ON "detector_feedback" USING btree ("security_event_id");