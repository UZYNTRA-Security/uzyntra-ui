ALTER TABLE "security_events" ADD COLUMN "detector_id" varchar(80);--> statement-breakpoint
ALTER TABLE "security_events" ADD COLUMN "detector_ids" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "security_events" ADD COLUMN "score" real;--> statement-breakpoint
ALTER TABLE "security_events" ADD COLUMN "api_route_id" text;--> statement-breakpoint
ALTER TABLE "security_events" ADD COLUMN "anomaly_type" varchar(80);--> statement-breakpoint
CREATE TABLE "api_inventory_routes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"route_template" text NOT NULL,
	"methods" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"status" varchar(32) DEFAULT 'new' NOT NULL,
	"observed_request_count" integer DEFAULT 0 NOT NULL,
	"observed_status_codes" integer[] DEFAULT ARRAY[]::integer[] NOT NULL,
	"content_types" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"learned_schema_summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "api_inventory_status_check" CHECK ("api_inventory_routes"."status" in ('new', 'known', 'approved', 'deprecated', 'unknown'))
);--> statement-breakpoint
CREATE TABLE "firewall_policy_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"previous_version" integer,
	"policy_mode" varchar(32) DEFAULT 'balanced' NOT NULL,
	"digest_sha256" varchar(64),
	"detector_exceptions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"policy_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_by" varchar(160),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "firewall_policy_versions_mode_check" CHECK ("firewall_policy_versions"."policy_mode" in ('monitor', 'balanced', 'strict'))
);--> statement-breakpoint
ALTER TABLE "api_inventory_routes" ADD CONSTRAINT "api_inventory_routes_org_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_inventory_routes" ADD CONSTRAINT "api_inventory_routes_fw_id_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_policy_versions" ADD CONSTRAINT "firewall_policy_versions_org_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_policy_versions" ADD CONSTRAINT "firewall_policy_versions_fw_id_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "security_events_detector_idx" ON "security_events" USING btree ("organization_id","detector_id");--> statement-breakpoint
CREATE INDEX "security_events_api_route_idx" ON "security_events" USING btree ("organization_id","api_route_id");--> statement-breakpoint
CREATE UNIQUE INDEX "api_inventory_route_unique_idx" ON "api_inventory_routes" USING btree ("organization_id","firewall_instance_id","route_template");--> statement-breakpoint
CREATE INDEX "api_inventory_org_status_idx" ON "api_inventory_routes" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "api_inventory_firewall_seen_idx" ON "api_inventory_routes" USING btree ("firewall_instance_id","last_seen_at");--> statement-breakpoint
CREATE UNIQUE INDEX "firewall_policy_versions_unique_idx" ON "firewall_policy_versions" USING btree ("organization_id","firewall_instance_id","version");--> statement-breakpoint
CREATE INDEX "firewall_policy_versions_firewall_idx" ON "firewall_policy_versions" USING btree ("firewall_instance_id","created_at");--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_score_check" CHECK ("security_events"."score" between 0 and 100);
