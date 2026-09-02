CREATE TABLE "identity_access_reviews" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"name" varchar(160) NOT NULL,
	"review_type" varchar(48) NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"scope" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"summary" text,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_by_user_id" uuid,
	"assigned_to_user_id" uuid,
	"due_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_access_reviews_type_chk" CHECK ("identity_access_reviews"."review_type" in ('periodic', 'privileged', 'inactive_accounts', 'orphaned_identities')),
	CONSTRAINT "identity_access_reviews_status_chk" CHECK ("identity_access_reviews"."status" in ('draft', 'open', 'in_review', 'completed', 'cancelled', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "identity_compliance_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"report_type" varchar(64) NOT NULL,
	"status" varchar(32) DEFAULT 'generated' NOT NULL,
	"window_start" timestamp with time zone,
	"window_end" timestamp with time zone,
	"generated_by_user_id" uuid,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"metrics" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"evidence_ref" varchar(160),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_compliance_reports_type_chk" CHECK ("identity_compliance_reports"."report_type" in ('user_inventory', 'mfa_status', 'privileged_access', 'sso_configuration', 'provisioning_history')),
	CONSTRAINT "identity_compliance_reports_status_chk" CHECK ("identity_compliance_reports"."status" in ('draft', 'generated', 'review_required', 'published', 'archived'))
);
--> statement-breakpoint
CREATE TABLE "identity_risk_scores" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid,
	"subject_type" varchar(48) DEFAULT 'user' NOT NULL,
	"subject_id" varchar(160),
	"score" integer DEFAULT 0 NOT NULL,
	"severity" varchar(32) DEFAULT 'low' NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"recommended_action" varchar(32) DEFAULT 'monitor' NOT NULL,
	"factors" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"last_signal_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_risk_scores_severity_chk" CHECK ("identity_risk_scores"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "identity_risk_scores_status_chk" CHECK ("identity_risk_scores"."status" in ('active', 'resolved', 'suppressed', 'expired')),
	CONSTRAINT "identity_risk_scores_action_chk" CHECK ("identity_risk_scores"."recommended_action" in ('monitor', 'require_mfa', 'restrict_session', 'alert')),
	CONSTRAINT "identity_risk_scores_score_chk" CHECK ("identity_risk_scores"."score" between 0 and 100),
	CONSTRAINT "identity_risk_scores_confidence_chk" CHECK ("identity_risk_scores"."confidence" between 0 and 1),
	CONSTRAINT "identity_risk_scores_subject_type_chk" CHECK ("identity_risk_scores"."subject_type" in ('user', 'client', 'provider', 'organization'))
);
--> statement-breakpoint
CREATE TABLE "identity_security_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid,
	"actor_user_id" uuid,
	"provider_id" uuid,
	"scim_provider_id" uuid,
	"audit_event_id" uuid,
	"event_type" varchar(160) NOT NULL,
	"category" varchar(48) NOT NULL,
	"result" varchar(32) DEFAULT 'success' NOT NULL,
	"severity" varchar(32) DEFAULT 'low' NOT NULL,
	"risk_score" integer DEFAULT 0 NOT NULL,
	"action" varchar(32) DEFAULT 'monitor' NOT NULL,
	"ip_address" varchar(45),
	"user_agent" text,
	"source" varchar(80) DEFAULT 'identity' NOT NULL,
	"summary" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identity_security_events_type_chk" CHECK ("identity_security_events"."event_type" in ('login.success', 'login.failure', 'mfa.failure', 'oauth.failure', 'sso.failure', 'scim.provisioning.failure', 'identity.change.suspicious', 'identity.risk.detected', 'identity.account.flagged')),
	CONSTRAINT "identity_security_events_category_chk" CHECK ("identity_security_events"."category" in ('authentication', 'mfa', 'oauth', 'sso', 'scim', 'governance', 'risk')),
	CONSTRAINT "identity_security_events_result_chk" CHECK ("identity_security_events"."result" in ('success', 'failure', 'denied', 'error')),
	CONSTRAINT "identity_security_events_severity_chk" CHECK ("identity_security_events"."severity" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "identity_security_events_action_chk" CHECK ("identity_security_events"."action" in ('monitor', 'require_mfa', 'restrict_session', 'alert')),
	CONSTRAINT "identity_security_events_risk_score_chk" CHECK ("identity_security_events"."risk_score" between 0 and 100)
);
--> statement-breakpoint
ALTER TABLE "identity_access_reviews" ADD CONSTRAINT "identity_access_reviews_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_access_reviews" ADD CONSTRAINT "identity_access_reviews_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_access_reviews" ADD CONSTRAINT "identity_access_reviews_assigned_to_user_id_users_id_fk" FOREIGN KEY ("assigned_to_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_compliance_reports" ADD CONSTRAINT "identity_compliance_reports_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_compliance_reports" ADD CONSTRAINT "identity_compliance_reports_generated_by_user_id_users_id_fk" FOREIGN KEY ("generated_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_risk_scores" ADD CONSTRAINT "identity_risk_scores_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_risk_scores" ADD CONSTRAINT "identity_risk_scores_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_provider_id_identity_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_scim_provider_id_scim_providers_id_fk" FOREIGN KEY ("scim_provider_id") REFERENCES "public"."scim_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_security_events" ADD CONSTRAINT "identity_security_events_audit_event_id_identity_audit_events_id_fk" FOREIGN KEY ("audit_event_id") REFERENCES "public"."identity_audit_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "identity_access_reviews_org_status_idx" ON "identity_access_reviews" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "identity_access_reviews_org_due_idx" ON "identity_access_reviews" USING btree ("organization_id","due_at");--> statement-breakpoint
CREATE INDEX "identity_access_reviews_type_idx" ON "identity_access_reviews" USING btree ("organization_id","review_type");--> statement-breakpoint
CREATE INDEX "identity_compliance_reports_org_type_idx" ON "identity_compliance_reports" USING btree ("organization_id","report_type");--> statement-breakpoint
CREATE INDEX "identity_compliance_reports_org_generated_idx" ON "identity_compliance_reports" USING btree ("organization_id","generated_at");--> statement-breakpoint
CREATE INDEX "identity_risk_scores_org_status_idx" ON "identity_risk_scores" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "identity_risk_scores_org_score_idx" ON "identity_risk_scores" USING btree ("organization_id","score");--> statement-breakpoint
CREATE INDEX "identity_risk_scores_user_idx" ON "identity_risk_scores" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "identity_risk_scores_subject_idx" ON "identity_risk_scores" USING btree ("organization_id","subject_type","subject_id");--> statement-breakpoint
CREATE INDEX "identity_security_events_org_created_idx" ON "identity_security_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_security_events_user_created_idx" ON "identity_security_events" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_security_events_type_created_idx" ON "identity_security_events" USING btree ("event_type","created_at");--> statement-breakpoint
CREATE INDEX "identity_security_events_risk_idx" ON "identity_security_events" USING btree ("organization_id","risk_score");
