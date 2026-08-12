CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"user_id" uuid,
	"service_account_id" uuid,
	"firewall_instance_id" uuid,
	"event_type" varchar(160) NOT NULL,
	"action" varchar(160) NOT NULL,
	"resource_type" varchar(120),
	"resource_id" varchar(160),
	"result" varchar(32) NOT NULL,
	"severity" varchar(32) DEFAULT 'info' NOT NULL,
	"ip_address" varchar(45),
	"user_agent" text,
	"request_id" varchar(160),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "audit_events_result_check" CHECK ("audit_events"."result" in ('success', 'failure', 'denied', 'error')),
	CONSTRAINT "audit_events_severity_check" CHECK ("audit_events"."severity" in ('info', 'low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_service_account_id_service_accounts_id_fk" FOREIGN KEY ("service_account_id") REFERENCES "public"."service_accounts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_firewall_instance_id_firewall_instances_id_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_events_organization_created_at_idx" ON "audit_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_events_user_created_at_idx" ON "audit_events" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_events_service_account_created_at_idx" ON "audit_events" USING btree ("service_account_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_events_firewall_instance_created_at_idx" ON "audit_events" USING btree ("firewall_instance_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_events_request_id_idx" ON "audit_events" USING btree ("request_id");