CREATE TABLE "break_glass_administrators" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"status" varchar(32) DEFAULT 'disabled' NOT NULL,
	"reason" text,
	"mfa_required" boolean DEFAULT true NOT NULL,
	"approved_by_user_id" uuid,
	"activated_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "break_glass_admins_status_chk" CHECK ("break_glass_administrators"."status" in ('active', 'disabled', 'expired', 'revoked'))
);
--> statement-breakpoint
CREATE TABLE "identity_audit_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"report_type" varchar(64) NOT NULL,
	"export_format" varchar(32) DEFAULT 'json' NOT NULL,
	"status" varchar(32) DEFAULT 'generated' NOT NULL,
	"window_start" timestamp with time zone,
	"window_end" timestamp with time zone,
	"generated_by_user_id" uuid,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"row_count" integer DEFAULT 0 NOT NULL,
	"report_payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"evidence_ref" varchar(160),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_audit_reports_type_chk" CHECK ("identity_audit_reports"."report_type" in ('administrator_activity', 'authentication_activity', 'provisioning_activity', 'access_review', 'identity_evidence')),
	CONSTRAINT "identity_audit_reports_format_chk" CHECK ("identity_audit_reports"."export_format" in ('csv', 'json', 'evidence_timeline')),
	CONSTRAINT "identity_audit_reports_status_chk" CHECK ("identity_audit_reports"."status" in ('draft', 'generated', 'review_required', 'published', 'archived')),
	CONSTRAINT "identity_audit_reports_row_count_chk" CHECK ("identity_audit_reports"."row_count" >= 0)
);
--> statement-breakpoint
CREATE TABLE "identity_metrics" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"metric_type" varchar(64) NOT NULL,
	"metric_value" real DEFAULT 0 NOT NULL,
	"numerator" integer DEFAULT 0 NOT NULL,
	"denominator" integer DEFAULT 0 NOT NULL,
	"status" varchar(32) DEFAULT 'unknown' NOT NULL,
	"bucket_start" timestamp with time zone NOT NULL,
	"bucket_end" timestamp with time zone NOT NULL,
	"dimensions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identity_metrics_type_chk" CHECK ("identity_metrics"."metric_type" in ('login_success_rate', 'login_failure_rate', 'mfa_success_rate', 'mfa_failure_rate', 'oauth_health', 'sso_health', 'scim_health', 'risky_identity_trend')),
	CONSTRAINT "identity_metrics_status_chk" CHECK ("identity_metrics"."status" in ('healthy', 'degraded', 'critical', 'unknown')),
	CONSTRAINT "identity_metrics_value_chk" CHECK ("identity_metrics"."metric_value" between 0 and 100),
	CONSTRAINT "identity_metrics_count_chk" CHECK ("identity_metrics"."numerator" >= 0 and "identity_metrics"."denominator" >= 0)
);
--> statement-breakpoint
CREATE TABLE "identity_recovery_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"workflow_id" uuid,
	"break_glass_administrator_id" uuid,
	"actor_user_id" uuid,
	"target_user_id" uuid,
	"event_type" varchar(160) NOT NULL,
	"result" varchar(32) DEFAULT 'success' NOT NULL,
	"summary" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identity_recovery_events_type_chk" CHECK ("identity_recovery_events"."event_type" in ('recovery.requested', 'recovery.approved', 'recovery.completed', 'recovery.rejected', 'break_glass.created', 'break_glass.activated', 'break_glass.revoked', 'recovery.tested')),
	CONSTRAINT "identity_recovery_events_result_chk" CHECK ("identity_recovery_events"."result" in ('success', 'failure', 'denied', 'error'))
);
--> statement-breakpoint
CREATE TABLE "identity_recovery_workflows" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"target_user_id" uuid,
	"requested_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"workflow_type" varchar(64) NOT NULL,
	"status" varchar(32) DEFAULT 'requested' NOT NULL,
	"reason" text,
	"mfa_required" boolean DEFAULT true NOT NULL,
	"approval_required" boolean DEFAULT true NOT NULL,
	"requested_at" timestamp with time zone DEFAULT now() NOT NULL,
	"approved_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_recovery_workflows_type_chk" CHECK ("identity_recovery_workflows"."workflow_type" in ('account_recovery', 'lockout_recovery', 'break_glass_activation', 'identity_disaster_recovery')),
	CONSTRAINT "identity_recovery_workflows_status_chk" CHECK ("identity_recovery_workflows"."status" in ('draft', 'requested', 'approved', 'active', 'completed', 'rejected', 'expired', 'cancelled'))
);
--> statement-breakpoint
ALTER TABLE "break_glass_administrators" ADD CONSTRAINT "break_glass_administrators_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "break_glass_administrators" ADD CONSTRAINT "break_glass_administrators_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "break_glass_administrators" ADD CONSTRAINT "break_glass_administrators_approved_by_user_id_users_id_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_reports" ADD CONSTRAINT "identity_audit_reports_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_reports" ADD CONSTRAINT "identity_audit_reports_generated_by_user_id_users_id_fk" FOREIGN KEY ("generated_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_metrics" ADD CONSTRAINT "identity_metrics_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_events" ADD CONSTRAINT "identity_recovery_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_events" ADD CONSTRAINT "identity_recovery_events_workflow_id_identity_recovery_workflows_id_fk" FOREIGN KEY ("workflow_id") REFERENCES "public"."identity_recovery_workflows"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_events" ADD CONSTRAINT "identity_recovery_events_break_glass_administrator_id_break_glass_administrators_id_fk" FOREIGN KEY ("break_glass_administrator_id") REFERENCES "public"."break_glass_administrators"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_events" ADD CONSTRAINT "identity_recovery_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_events" ADD CONSTRAINT "identity_recovery_events_target_user_id_users_id_fk" FOREIGN KEY ("target_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_workflows" ADD CONSTRAINT "identity_recovery_workflows_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_workflows" ADD CONSTRAINT "identity_recovery_workflows_target_user_id_users_id_fk" FOREIGN KEY ("target_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_workflows" ADD CONSTRAINT "identity_recovery_workflows_requested_by_user_id_users_id_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_recovery_workflows" ADD CONSTRAINT "identity_recovery_workflows_approved_by_user_id_users_id_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "break_glass_admins_org_user_idx" ON "break_glass_administrators" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "break_glass_admins_org_status_idx" ON "break_glass_administrators" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "break_glass_admins_expires_idx" ON "break_glass_administrators" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "identity_audit_reports_org_type_idx" ON "identity_audit_reports" USING btree ("organization_id","report_type");--> statement-breakpoint
CREATE INDEX "identity_audit_reports_org_generated_idx" ON "identity_audit_reports" USING btree ("organization_id","generated_at");--> statement-breakpoint
CREATE INDEX "identity_metrics_org_type_bucket_idx" ON "identity_metrics" USING btree ("organization_id","metric_type","bucket_start");--> statement-breakpoint
CREATE INDEX "identity_metrics_org_status_idx" ON "identity_metrics" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "identity_recovery_events_org_created_idx" ON "identity_recovery_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_recovery_events_workflow_idx" ON "identity_recovery_events" USING btree ("workflow_id");--> statement-breakpoint
CREATE INDEX "identity_recovery_events_target_idx" ON "identity_recovery_events" USING btree ("target_user_id");--> statement-breakpoint
CREATE INDEX "identity_recovery_workflows_org_status_idx" ON "identity_recovery_workflows" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "identity_recovery_workflows_target_idx" ON "identity_recovery_workflows" USING btree ("target_user_id");--> statement-breakpoint
CREATE INDEX "identity_recovery_workflows_expires_idx" ON "identity_recovery_workflows" USING btree ("expires_at");