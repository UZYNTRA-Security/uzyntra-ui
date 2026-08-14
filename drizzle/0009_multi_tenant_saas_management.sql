CREATE TABLE "firewall_enrollment_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "firewall_enrollment_tokens_status_check" CHECK ("firewall_enrollment_tokens"."status" in ('pending', 'used', 'revoked', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "firewall_instance_service_account_role_assignments" (
	"firewall_instance_id" uuid NOT NULL,
	"service_account_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "fisara_pk" PRIMARY KEY("firewall_instance_id","service_account_id","role_id")
);
--> statement-breakpoint
CREATE TABLE "organization_invitations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"email" varchar(320) NOT NULL,
	"invited_by_user_id" uuid,
	"role_id" uuid,
	"token_hash" text NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"accepted_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organization_invitations_status_check" CHECK ("organization_invitations"."status" in ('pending', 'accepted', 'revoked', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "service_account_roles" (
	"service_account_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "service_account_roles_service_account_id_role_id_pk" PRIMARY KEY("service_account_id","role_id")
);
--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "installation_identifier" varchar(160);--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "hostname" varchar(255);--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "region" varchar(80);--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "version" varchar(80);--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "enrolled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "last_seen_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "firewall_instances" ADD COLUMN "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "active_firewall_instance_id" uuid;--> statement-breakpoint
ALTER TABLE "firewall_enrollment_tokens" ADD CONSTRAINT "fet_organization_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_enrollment_tokens" ADD CONSTRAINT "fet_firewall_instance_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_enrollment_tokens" ADD CONSTRAINT "fet_created_by_user_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_instance_service_account_role_assignments" ADD CONSTRAINT "fisara_firewall_instance_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_instance_service_account_role_assignments" ADD CONSTRAINT "fisara_service_account_fk" FOREIGN KEY ("service_account_id") REFERENCES "public"."service_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_instance_service_account_role_assignments" ADD CONSTRAINT "fisara_role_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_invitations" ADD CONSTRAINT "organization_invitations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_invitations" ADD CONSTRAINT "organization_invitations_invited_by_user_id_users_id_fk" FOREIGN KEY ("invited_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_invitations" ADD CONSTRAINT "organization_invitations_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_account_roles" ADD CONSTRAINT "service_account_roles_service_account_id_service_accounts_id_fk" FOREIGN KEY ("service_account_id") REFERENCES "public"."service_accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "service_account_roles" ADD CONSTRAINT "service_account_roles_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "firewall_enrollment_tokens_token_hash_idx" ON "firewall_enrollment_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "firewall_enrollment_tokens_organization_id_idx" ON "firewall_enrollment_tokens" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "firewall_enrollment_tokens_firewall_instance_id_idx" ON "firewall_enrollment_tokens" USING btree ("firewall_instance_id");--> statement-breakpoint
CREATE INDEX "firewall_enrollment_tokens_expires_at_idx" ON "firewall_enrollment_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "firewall_instance_service_account_roles_service_account_id_idx" ON "firewall_instance_service_account_role_assignments" USING btree ("service_account_id");--> statement-breakpoint
CREATE INDEX "firewall_instance_service_account_roles_role_id_idx" ON "firewall_instance_service_account_role_assignments" USING btree ("role_id");--> statement-breakpoint
CREATE UNIQUE INDEX "organization_invitations_token_hash_idx" ON "organization_invitations" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "organization_invitations_organization_id_idx" ON "organization_invitations" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "organization_invitations_email_idx" ON "organization_invitations" USING btree ("email");--> statement-breakpoint
CREATE INDEX "organization_invitations_expires_at_idx" ON "organization_invitations" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "service_account_roles_role_id_idx" ON "service_account_roles" USING btree ("role_id");--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_active_firewall_instance_id_firewall_instances_id_fk" FOREIGN KEY ("active_firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "firewall_instances_installation_identifier_idx" ON "firewall_instances" USING btree ("installation_identifier") WHERE installation_identifier IS NOT NULL;--> statement-breakpoint
CREATE INDEX "firewall_instances_organization_status_idx" ON "firewall_instances" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "sessions_active_firewall_instance_id_idx" ON "sessions" USING btree ("active_firewall_instance_id");
