CREATE TABLE "scim_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider_id" uuid,
	"sync_job_id" uuid,
	"user_id" uuid,
	"membership_id" uuid,
	"event_type" varchar(160) NOT NULL,
	"result" varchar(32) NOT NULL,
	"external_id_hash" text,
	"resource_type" varchar(32),
	"resource_id" varchar(255),
	"summary" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scim_events_type_chk" CHECK ("scim_events"."event_type" in ('scim.user.created', 'scim.user.updated', 'scim.user.deactivated', 'scim.group.synced', 'scim.sync.started', 'scim.sync.completed', 'scim.sync.failed')),
	CONSTRAINT "scim_events_result_chk" CHECK ("scim_events"."result" in ('success', 'failure', 'denied', 'error'))
);
--> statement-breakpoint
CREATE TABLE "scim_group_mappings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_group_id_hash" text NOT NULL,
	"external_display_name" varchar(160) NOT NULL,
	"role_id" uuid,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"approved_by_user_id" uuid,
	"approved_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scim_group_mappings_status_chk" CHECK ("scim_group_mappings"."status" in ('pending', 'approved', 'disabled', 'deleted'))
);
--> statement-breakpoint
CREATE TABLE "scim_providers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'disabled' NOT NULL,
	"endpoint_configuration_ref" varchar(160),
	"base_url" text,
	"created_by_user_id" uuid,
	"last_sync_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "scim_providers_status_chk" CHECK ("scim_providers"."status" in ('active', 'disabled', 'deleted'))
);
--> statement-breakpoint
CREATE TABLE "scim_sync_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider_id" uuid,
	"operation_type" varchar(48) NOT NULL,
	"status" varchar(32) DEFAULT 'queued' NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"error_summary" text,
	"resource_type" varchar(32),
	"resource_id" varchar(255),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scim_sync_jobs_operation_chk" CHECK ("scim_sync_jobs"."operation_type" in ('user_create', 'user_update', 'user_deactivate', 'group_sync', 'full_sync')),
	CONSTRAINT "scim_sync_jobs_status_chk" CHECK ("scim_sync_jobs"."status" in ('queued', 'running', 'completed', 'failed', 'cancelled'))
);
--> statement-breakpoint
CREATE TABLE "scim_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"name" varchar(160) DEFAULT 'SCIM token' NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"last_used_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "scim_tokens_status_chk" CHECK ("scim_tokens"."status" in ('active', 'revoked', 'expired'))
);
--> statement-breakpoint
ALTER TABLE "scim_events" ADD CONSTRAINT "scim_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_events" ADD CONSTRAINT "scim_events_provider_id_scim_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."scim_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_events" ADD CONSTRAINT "scim_events_sync_job_id_scim_sync_jobs_id_fk" FOREIGN KEY ("sync_job_id") REFERENCES "public"."scim_sync_jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_events" ADD CONSTRAINT "scim_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_events" ADD CONSTRAINT "scim_events_membership_id_organization_memberships_id_fk" FOREIGN KEY ("membership_id") REFERENCES "public"."organization_memberships"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_mappings" ADD CONSTRAINT "scim_group_mappings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_mappings" ADD CONSTRAINT "scim_group_mappings_provider_id_scim_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."scim_providers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_mappings" ADD CONSTRAINT "scim_group_mappings_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_group_mappings" ADD CONSTRAINT "scim_group_mappings_approved_by_user_id_users_id_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_providers" ADD CONSTRAINT "scim_providers_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_providers" ADD CONSTRAINT "scim_providers_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_sync_jobs" ADD CONSTRAINT "scim_sync_jobs_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_sync_jobs" ADD CONSTRAINT "scim_sync_jobs_provider_id_scim_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."scim_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_provider_id_scim_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."scim_providers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_tokens" ADD CONSTRAINT "scim_tokens_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "scim_events_org_created_idx" ON "scim_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "scim_events_provider_created_idx" ON "scim_events" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "scim_events_user_created_idx" ON "scim_events" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "scim_events_external_idx" ON "scim_events" USING btree ("external_id_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "scim_group_mappings_provider_group_idx" ON "scim_group_mappings" USING btree ("provider_id","external_group_id_hash");--> statement-breakpoint
CREATE INDEX "scim_group_mappings_org_status_idx" ON "scim_group_mappings" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "scim_group_mappings_role_idx" ON "scim_group_mappings" USING btree ("role_id");--> statement-breakpoint
CREATE UNIQUE INDEX "scim_providers_org_name_idx" ON "scim_providers" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "scim_providers_org_status_idx" ON "scim_providers" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "scim_sync_jobs_org_status_idx" ON "scim_sync_jobs" USING btree ("organization_id","status","created_at");--> statement-breakpoint
CREATE INDEX "scim_sync_jobs_provider_status_idx" ON "scim_sync_jobs" USING btree ("provider_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "scim_tokens_hash_idx" ON "scim_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "scim_tokens_org_provider_status_idx" ON "scim_tokens" USING btree ("organization_id","provider_id","status");--> statement-breakpoint
CREATE INDEX "scim_tokens_expires_idx" ON "scim_tokens" USING btree ("expires_at");