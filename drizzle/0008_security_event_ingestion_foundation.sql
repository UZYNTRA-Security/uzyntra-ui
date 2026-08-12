CREATE TABLE "security_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"event_type" varchar(80) NOT NULL,
	"attack_type" varchar(80) NOT NULL,
	"severity" varchar(32) NOT NULL,
	"source_ip" varchar(45),
	"request_path" text,
	"http_method" varchar(16),
	"user_agent" text,
	"country" varchar(2),
	"confidence" real,
	"action_taken" varchar(32) NOT NULL,
	"request_id" varchar(160),
	"raw_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "security_events_severity_check" CHECK ("security_events"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "security_events_action_taken_check" CHECK ("security_events"."action_taken" in ('blocked', 'allowed', 'rate_limited', 'challenged')),
	CONSTRAINT "security_events_confidence_check" CHECK ("security_events"."confidence" between 0 and 1)
);
--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_firewall_instance_id_firewall_instances_id_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "security_events_organization_occurred_at_idx" ON "security_events" USING btree ("organization_id","occurred_at");--> statement-breakpoint
CREATE INDEX "security_events_firewall_occurred_at_idx" ON "security_events" USING btree ("firewall_instance_id","occurred_at");--> statement-breakpoint
CREATE INDEX "security_events_organization_severity_occurred_at_idx" ON "security_events" USING btree ("organization_id","severity","occurred_at");--> statement-breakpoint
CREATE INDEX "security_events_organization_attack_type_occurred_at_idx" ON "security_events" USING btree ("organization_id","attack_type","occurred_at");--> statement-breakpoint
CREATE INDEX "security_events_request_id_idx" ON "security_events" USING btree ("request_id");