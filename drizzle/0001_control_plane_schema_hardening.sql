CREATE TABLE "organization_settings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"mfa_required" boolean DEFAULT false NOT NULL,
	"session_timeout_seconds" integer DEFAULT 28800 NOT NULL,
	"allowed_email_domains" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"security_level" varchar(32) DEFAULT 'standard' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organization_settings_security_level_check" CHECK ("organization_settings"."security_level" in ('standard', 'strict', 'enterprise')),
	CONSTRAINT "organization_settings_session_timeout_seconds_check" CHECK ("organization_settings"."session_timeout_seconds" between 300 and 2592000)
);
--> statement-breakpoint
DROP INDEX "api_keys_key_prefix_idx";--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "service_accounts" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "deleted_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "organization_settings" ADD CONSTRAINT "organization_settings_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "organization_settings_organization_id_idx" ON "organization_settings" USING btree ("organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "api_keys_key_prefix_idx" ON "api_keys" USING btree ("key_prefix");--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_status_check" CHECK ("api_keys"."status" in ('active', 'disabled', 'deleted'));--> statement-breakpoint
ALTER TABLE "audit_actors" ADD CONSTRAINT "audit_actors_actor_type_check" CHECK ("audit_actors"."actor_type" in ('user', 'service_account', 'api_key', 'system'));--> statement-breakpoint
ALTER TABLE "audit_actors" ADD CONSTRAINT "audit_actors_reference_check" CHECK (
        (
          "audit_actors"."actor_type" = 'user'
          and "audit_actors"."user_id" is not null
          and "audit_actors"."service_account_id" is null
          and "audit_actors"."api_key_id" is null
        )
        or (
          "audit_actors"."actor_type" = 'service_account'
          and "audit_actors"."user_id" is null
          and "audit_actors"."service_account_id" is not null
          and "audit_actors"."api_key_id" is null
        )
        or (
          "audit_actors"."actor_type" = 'api_key'
          and "audit_actors"."user_id" is null
          and "audit_actors"."service_account_id" is null
          and "audit_actors"."api_key_id" is not null
        )
        or (
          "audit_actors"."actor_type" = 'system'
          and "audit_actors"."user_id" is null
          and "audit_actors"."service_account_id" is null
          and "audit_actors"."api_key_id" is null
        )
      );--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD CONSTRAINT "firewall_instances_status_check" CHECK ("firewall_instances"."status" in ('active', 'disabled', 'deleted'));--> statement-breakpoint
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_status_check" CHECK ("organizations"."status" in ('active', 'disabled', 'deleted'));--> statement-breakpoint
ALTER TABLE "service_accounts" ADD CONSTRAINT "service_accounts_status_check" CHECK ("service_accounts"."status" in ('active', 'disabled', 'deleted'));--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_status_check" CHECK ("users"."status" in ('active', 'disabled', 'deleted'));