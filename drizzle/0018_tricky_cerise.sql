CREATE TABLE "sso_login_attempts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"provider_id" uuid NOT NULL,
	"flow_type" varchar(32) NOT NULL,
	"state_hash" text NOT NULL,
	"pkce_verifier_hash" text,
	"assertion_id_hash" text,
	"authorization_code_hash" text,
	"redirect_path" varchar(255) DEFAULT '/' NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"ip_address" varchar(45),
	"user_agent" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "sso_login_attempts_flow_chk" CHECK ("sso_login_attempts"."flow_type" in ('saml', 'oidc')),
	CONSTRAINT "sso_login_attempts_status_chk" CHECK ("sso_login_attempts"."status" in ('pending', 'completed', 'failed', 'expired'))
);
--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "allowed_domains" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "configuration_ref" varchar(160);--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "secret_ref" varchar(160);--> statement-breakpoint
ALTER TABLE "organization_settings" ADD COLUMN "sso_mode" varchar(32) DEFAULT 'optional' NOT NULL;--> statement-breakpoint
ALTER TABLE "organization_settings" ADD COLUMN "sso_allowed_domains" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "organization_settings" ADD COLUMN "sso_password_login_disabled" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "organization_settings" ADD COLUMN "sso_mfa_required" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "sso_login_attempts" ADD CONSTRAINT "sso_login_attempts_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sso_login_attempts" ADD CONSTRAINT "sso_login_attempts_provider_id_identity_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "sso_login_attempts_state_idx" ON "sso_login_attempts" USING btree ("state_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "sso_login_attempts_assertion_idx" ON "sso_login_attempts" USING btree ("assertion_id_hash") WHERE assertion_id_hash IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "sso_login_attempts_code_idx" ON "sso_login_attempts" USING btree ("authorization_code_hash") WHERE authorization_code_hash IS NOT NULL;--> statement-breakpoint
CREATE INDEX "sso_login_attempts_org_provider_status_idx" ON "sso_login_attempts" USING btree ("organization_id","provider_id","status");--> statement-breakpoint
CREATE INDEX "sso_login_attempts_expires_idx" ON "sso_login_attempts" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "identity_providers_org_type_idx" ON "identity_providers" USING btree ("organization_id","provider_type");--> statement-breakpoint
ALTER TABLE "organization_settings" ADD CONSTRAINT "organization_settings_sso_mode_check" CHECK ("organization_settings"."sso_mode" in ('optional', 'required', 'disabled'));