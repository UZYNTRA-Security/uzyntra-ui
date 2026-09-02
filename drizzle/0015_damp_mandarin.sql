CREATE TABLE "external_identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"external_subject_hash" text NOT NULL,
	"provider_email" varchar(320),
	"provider_email_hash" text,
	"email_verified" boolean DEFAULT false NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"linked_at" timestamp with time zone DEFAULT now() NOT NULL,
	"unlinked_at" timestamp with time zone,
	"last_seen_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "external_identities_status_chk" CHECK ("external_identities"."status" in ('active', 'unlinked', 'disabled', 'deleted'))
);
--> statement-breakpoint
CREATE TABLE "identity_audit_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"user_id" uuid,
	"actor_user_id" uuid,
	"provider_id" uuid,
	"external_identity_id" uuid,
	"event_type" varchar(160) NOT NULL,
	"action" varchar(160) NOT NULL,
	"result" varchar(32) NOT NULL,
	"ip_address" varchar(45),
	"user_agent" text,
	"request_id" varchar(160),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "identity_audit_events_result_chk" CHECK ("identity_audit_events"."result" in ('success', 'failure', 'denied', 'error'))
);
--> statement-breakpoint
CREATE TABLE "identity_providers" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"provider_key" varchar(80) NOT NULL,
	"provider_type" varchar(32) NOT NULL,
	"display_name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'disabled' NOT NULL,
	"issuer" varchar(255),
	"client_id" varchar(255),
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "identity_providers_type_chk" CHECK ("identity_providers"."provider_type" in ('password', 'google', 'github', 'oidc', 'saml')),
	CONSTRAINT "identity_providers_status_chk" CHECK ("identity_providers"."status" in ('active', 'disabled', 'deleted'))
);
--> statement-breakpoint
INSERT INTO "identity_providers" (
	"provider_key",
	"provider_type",
	"display_name",
	"status",
	"is_system"
) VALUES
	('password', 'password', 'Password', 'active', true),
	('google', 'google', 'Google', 'disabled', true),
	('github', 'github', 'GitHub', 'disabled', true),
	('oidc', 'oidc', 'OpenID Connect', 'disabled', true),
	('saml', 'saml', 'SAML', 'disabled', true)
ON CONFLICT ("provider_key") WHERE "organization_id" IS NULL DO NOTHING;
--> statement-breakpoint
CREATE TABLE "verified_email_identities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"email" varchar(320) NOT NULL,
	"email_hash" text NOT NULL,
	"source_provider_id" uuid,
	"verification_source" varchar(32) DEFAULT 'password' NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"verified_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "verified_email_identities_status_chk" CHECK ("verified_email_identities"."status" in ('active', 'revoked', 'expired')),
	CONSTRAINT "verified_email_identities_source_chk" CHECK ("verified_email_identities"."verification_source" in ('password', 'google', 'github', 'oidc', 'saml', 'manual'))
);
--> statement-breakpoint
ALTER TABLE "external_identities" ADD CONSTRAINT "external_identities_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "external_identities" ADD CONSTRAINT "external_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "external_identities" ADD CONSTRAINT "external_identities_provider_id_identity_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_events" ADD CONSTRAINT "identity_audit_events_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_events" ADD CONSTRAINT "identity_audit_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_events" ADD CONSTRAINT "identity_audit_events_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_events" ADD CONSTRAINT "identity_audit_events_provider_id_identity_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_audit_events" ADD CONSTRAINT "identity_audit_events_external_identity_id_external_identities_id_fk" FOREIGN KEY ("external_identity_id") REFERENCES "public"."external_identities"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD CONSTRAINT "identity_providers_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD CONSTRAINT "identity_providers_created_by_user_id_users_id_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "verified_email_identities" ADD CONSTRAINT "verified_email_identities_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "verified_email_identities" ADD CONSTRAINT "verified_email_identities_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "verified_email_identities" ADD CONSTRAINT "verified_email_identities_source_provider_id_identity_providers_id_fk" FOREIGN KEY ("source_provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "external_identities_provider_subject_idx" ON "external_identities" USING btree ("provider_id","external_subject_hash");--> statement-breakpoint
CREATE INDEX "external_identities_org_user_idx" ON "external_identities" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "external_identities_org_provider_idx" ON "external_identities" USING btree ("organization_id","provider_id");--> statement-breakpoint
CREATE INDEX "external_identities_email_hash_idx" ON "external_identities" USING btree ("provider_email_hash");--> statement-breakpoint
CREATE INDEX "identity_audit_events_org_created_idx" ON "identity_audit_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_audit_events_user_created_idx" ON "identity_audit_events" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_audit_events_actor_created_idx" ON "identity_audit_events" USING btree ("actor_user_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_audit_events_provider_created_idx" ON "identity_audit_events" USING btree ("provider_id","created_at");--> statement-breakpoint
CREATE INDEX "identity_audit_events_request_id_idx" ON "identity_audit_events" USING btree ("request_id");--> statement-breakpoint
CREATE UNIQUE INDEX "identity_providers_org_key_idx" ON "identity_providers" USING btree ("organization_id","provider_key");--> statement-breakpoint
CREATE UNIQUE INDEX "identity_providers_global_key_idx" ON "identity_providers" USING btree ("provider_key") WHERE organization_id IS NULL;--> statement-breakpoint
CREATE INDEX "identity_providers_org_status_idx" ON "identity_providers" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "identity_providers_type_status_idx" ON "identity_providers" USING btree ("provider_type","status");--> statement-breakpoint
CREATE UNIQUE INDEX "verified_email_identities_org_email_idx" ON "verified_email_identities" USING btree ("organization_id","email_hash");--> statement-breakpoint
CREATE INDEX "verified_email_identities_user_idx" ON "verified_email_identities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "verified_email_identities_source_idx" ON "verified_email_identities" USING btree ("source_provider_id");
