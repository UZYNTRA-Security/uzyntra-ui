CREATE TABLE "reputation_cache" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"indicator_type" varchar(32) NOT NULL,
	"lookup_hash" varchar(64) NOT NULL,
	"lookup_label" varchar(240),
	"reputation_score" real DEFAULT 0 NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"categories" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"source_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"indicator_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_refreshed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "reputation_cache_type_chk" CHECK ("reputation_cache"."indicator_type" in ('ip', 'cidr', 'domain', 'url', 'hash', 'asn', 'user_agent')),
	CONSTRAINT "reputation_cache_score_chk" CHECK ("reputation_cache"."reputation_score" between 0 and 100),
	CONSTRAINT "reputation_cache_confidence_chk" CHECK ("reputation_cache"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "threat_feed_status" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source_id" uuid NOT NULL,
	"feed_name" varchar(160) NOT NULL,
	"sync_cursor" text,
	"sync_status" varchar(32) DEFAULT 'idle' NOT NULL,
	"last_started_at" timestamp with time zone,
	"last_completed_at" timestamp with time zone,
	"last_error_code" varchar(80),
	"items_processed" integer DEFAULT 0 NOT NULL,
	"items_rejected" integer DEFAULT 0 NOT NULL,
	"items_expired" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "threat_feed_status_status_chk" CHECK ("threat_feed_status"."sync_status" in ('idle', 'running', 'success', 'failed', 'rate_limited')),
	CONSTRAINT "threat_feed_status_counts_chk" CHECK ("threat_feed_status"."items_processed" >= 0 and "threat_feed_status"."items_rejected" >= 0 and "threat_feed_status"."items_expired" >= 0)
);
--> statement-breakpoint
CREATE TABLE "threat_indicators" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"source_id" uuid,
	"indicator_type" varchar(32) NOT NULL,
	"indicator_value_hash" varchar(64) NOT NULL,
	"indicator_value_display" varchar(240) NOT NULL,
	"category" varchar(80) DEFAULT 'unknown' NOT NULL,
	"reputation_score" real DEFAULT 0 NOT NULL,
	"confidence" real DEFAULT 0.5 NOT NULL,
	"severity" varchar(32) DEFAULT 'medium' NOT NULL,
	"tags" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"review_status" varchar(32) DEFAULT 'unreviewed' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"source_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"reviewed_by_user_id" uuid,
	"reviewed_at" timestamp with time zone,
	"analyst_note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "threat_indicators_type_chk" CHECK ("threat_indicators"."indicator_type" in ('ip', 'cidr', 'domain', 'url', 'hash', 'asn', 'user_agent')),
	CONSTRAINT "threat_indicators_review_status_chk" CHECK ("threat_indicators"."review_status" in ('unreviewed', 'confirmed', 'false_positive', 'trusted', 'expired')),
	CONSTRAINT "threat_indicators_severity_chk" CHECK ("threat_indicators"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "threat_indicators_reputation_chk" CHECK ("threat_indicators"."reputation_score" between 0 and 100),
	CONSTRAINT "threat_indicators_confidence_chk" CHECK ("threat_indicators"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "threat_matches" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"security_event_id" uuid,
	"detection_finding_id" uuid,
	"correlation_event_id" uuid,
	"indicator_id" uuid,
	"indicator_type" varchar(32) NOT NULL,
	"match_value_hash" varchar(64) NOT NULL,
	"match_label" varchar(240),
	"match_context" varchar(80) NOT NULL,
	"risk_delta" real DEFAULT 0 NOT NULL,
	"confidence_delta" real DEFAULT 0 NOT NULL,
	"source_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"matched_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "threat_matches_type_chk" CHECK ("threat_matches"."indicator_type" in ('ip', 'cidr', 'domain', 'url', 'hash', 'asn', 'user_agent')),
	CONSTRAINT "threat_matches_risk_delta_chk" CHECK ("threat_matches"."risk_delta" between -100 and 100),
	CONSTRAINT "threat_matches_confidence_delta_chk" CHECK ("threat_matches"."confidence_delta" between -1 and 1)
);
--> statement-breakpoint
CREATE TABLE "threat_sources" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"name" varchar(160) NOT NULL,
	"provider_type" varchar(80) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"health_status" varchar(32) DEFAULT 'unknown' NOT NULL,
	"capabilities" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"secret_reference" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"rate_limit_per_minute" integer DEFAULT 60 NOT NULL,
	"timeout_ms" integer DEFAULT 2500 NOT NULL,
	"last_sync_at" timestamp with time zone,
	"last_success_at" timestamp with time zone,
	"last_failure_at" timestamp with time zone,
	"last_failure_code" varchar(80),
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "threat_sources_status_chk" CHECK ("threat_sources"."status" in ('active', 'observe', 'disabled', 'deleted')),
	CONSTRAINT "threat_sources_health_chk" CHECK ("threat_sources"."health_status" in ('healthy', 'degraded', 'failed', 'unknown')),
	CONSTRAINT "threat_sources_rate_limit_chk" CHECK ("threat_sources"."rate_limit_per_minute" between 1 and 10000),
	CONSTRAINT "threat_sources_timeout_chk" CHECK ("threat_sources"."timeout_ms" between 100 and 30000)
);
--> statement-breakpoint
ALTER TABLE "reputation_cache" ADD CONSTRAINT "reputation_cache_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_feed_status" ADD CONSTRAINT "threat_feed_status_source_fk" FOREIGN KEY ("source_id") REFERENCES "public"."threat_sources"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicators" ADD CONSTRAINT "threat_indicators_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicators" ADD CONSTRAINT "threat_indicators_source_fk" FOREIGN KEY ("source_id") REFERENCES "public"."threat_sources"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_indicators" ADD CONSTRAINT "threat_indicators_reviewed_by_fk" FOREIGN KEY ("reviewed_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_security_event_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_detection_finding_fk" FOREIGN KEY ("detection_finding_id") REFERENCES "public"."detection_findings"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_correlation_event_fk" FOREIGN KEY ("correlation_event_id") REFERENCES "public"."correlation_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_indicator_fk" FOREIGN KEY ("indicator_id") REFERENCES "public"."threat_indicators"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_matches" ADD CONSTRAINT "threat_matches_source_fk" FOREIGN KEY ("source_id") REFERENCES "public"."threat_sources"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_sources" ADD CONSTRAINT "threat_sources_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "threat_sources" ADD CONSTRAINT "threat_sources_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "reputation_cache_org_lookup_idx" ON "reputation_cache" USING btree ("organization_id","indicator_type","lookup_hash");--> statement-breakpoint
CREATE INDEX "reputation_cache_lookup_idx" ON "reputation_cache" USING btree ("indicator_type","lookup_hash");--> statement-breakpoint
CREATE INDEX "reputation_cache_expires_idx" ON "reputation_cache" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "threat_feed_status_source_feed_idx" ON "threat_feed_status" USING btree ("source_id","feed_name");--> statement-breakpoint
CREATE INDEX "threat_feed_status_source_status_idx" ON "threat_feed_status" USING btree ("source_id","sync_status");--> statement-breakpoint
CREATE INDEX "threat_feed_status_completed_idx" ON "threat_feed_status" USING btree ("last_completed_at");--> statement-breakpoint
CREATE INDEX "threat_indicators_lookup_idx" ON "threat_indicators" USING btree ("indicator_type","indicator_value_hash");--> statement-breakpoint
CREATE INDEX "threat_indicators_org_lookup_idx" ON "threat_indicators" USING btree ("organization_id","indicator_type","indicator_value_hash");--> statement-breakpoint
CREATE INDEX "threat_indicators_source_seen_idx" ON "threat_indicators" USING btree ("source_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "threat_indicators_expires_idx" ON "threat_indicators" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "threat_indicators_category_score_idx" ON "threat_indicators" USING btree ("category","reputation_score");--> statement-breakpoint
CREATE INDEX "threat_matches_org_time_idx" ON "threat_matches" USING btree ("organization_id","matched_at");--> statement-breakpoint
CREATE INDEX "threat_matches_firewall_time_idx" ON "threat_matches" USING btree ("firewall_instance_id","matched_at");--> statement-breakpoint
CREATE INDEX "threat_matches_event_idx" ON "threat_matches" USING btree ("security_event_id");--> statement-breakpoint
CREATE INDEX "threat_matches_indicator_time_idx" ON "threat_matches" USING btree ("indicator_id","matched_at");--> statement-breakpoint
CREATE INDEX "threat_matches_lookup_idx" ON "threat_matches" USING btree ("indicator_type","match_value_hash");--> statement-breakpoint
CREATE INDEX "threat_sources_org_status_idx" ON "threat_sources" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "threat_sources_provider_status_idx" ON "threat_sources" USING btree ("provider_type","status");--> statement-breakpoint
CREATE INDEX "threat_sources_health_idx" ON "threat_sources" USING btree ("health_status","last_sync_at");