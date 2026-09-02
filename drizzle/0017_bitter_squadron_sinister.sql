CREATE TABLE "mfa_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"method_id" uuid,
	"challenge_type" varchar(32) DEFAULT 'login' NOT NULL,
	"challenge_hash" text NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"attempt_count" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 5 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"succeeded_at" timestamp with time zone,
	"consumed_at" timestamp with time zone,
	"ip_address" varchar(45),
	"user_agent" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "mfa_challenges_type_chk" CHECK ("mfa_challenges"."challenge_type" in ('login', 'step_up', 'registration')),
	CONSTRAINT "mfa_challenges_status_chk" CHECK ("mfa_challenges"."status" in ('pending', 'succeeded', 'failed', 'expired')),
	CONSTRAINT "mfa_challenges_attempt_count_chk" CHECK ("mfa_challenges"."attempt_count" >= 0),
	CONSTRAINT "mfa_challenges_max_attempts_chk" CHECK ("mfa_challenges"."max_attempts" between 1 and 10)
);
--> statement-breakpoint
CREATE TABLE "mfa_methods" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"method_type" varchar(32) NOT NULL,
	"display_name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"verified_at" timestamp with time zone,
	"enabled_at" timestamp with time zone,
	"disabled_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"secret_ciphertext" jsonb,
	"credential_id_hash" text,
	"public_key" text,
	"sign_count" integer DEFAULT 0 NOT NULL,
	"device_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "mfa_methods_type_chk" CHECK ("mfa_methods"."method_type" in ('totp', 'webauthn', 'recovery_codes')),
	CONSTRAINT "mfa_methods_status_chk" CHECK ("mfa_methods"."status" in ('pending', 'active', 'disabled', 'deleted')),
	CONSTRAINT "mfa_methods_sign_count_chk" CHECK ("mfa_methods"."sign_count" >= 0)
);
--> statement-breakpoint
CREATE TABLE "recovery_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"method_id" uuid,
	"code_hash" text NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "recovery_codes_status_chk" CHECK ("recovery_codes"."status" in ('active', 'used', 'revoked'))
);
--> statement-breakpoint
ALTER TABLE "mfa_challenges" ADD CONSTRAINT "mfa_challenges_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_challenges" ADD CONSTRAINT "mfa_challenges_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_challenges" ADD CONSTRAINT "mfa_challenges_method_id_mfa_methods_id_fk" FOREIGN KEY ("method_id") REFERENCES "public"."mfa_methods"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_methods" ADD CONSTRAINT "mfa_methods_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_methods" ADD CONSTRAINT "mfa_methods_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_codes" ADD CONSTRAINT "recovery_codes_method_id_mfa_methods_id_fk" FOREIGN KEY ("method_id") REFERENCES "public"."mfa_methods"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_challenges_hash_idx" ON "mfa_challenges" USING btree ("challenge_hash");--> statement-breakpoint
CREATE INDEX "mfa_challenges_user_status_idx" ON "mfa_challenges" USING btree ("user_id","status");--> statement-breakpoint
CREATE INDEX "mfa_challenges_org_status_idx" ON "mfa_challenges" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "mfa_challenges_expires_idx" ON "mfa_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "mfa_methods_org_user_idx" ON "mfa_methods" USING btree ("organization_id","user_id");--> statement-breakpoint
CREATE INDEX "mfa_methods_user_status_idx" ON "mfa_methods" USING btree ("user_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "mfa_methods_credential_id_idx" ON "mfa_methods" USING btree ("credential_id_hash") WHERE credential_id_hash IS NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "recovery_codes_hash_idx" ON "recovery_codes" USING btree ("code_hash");--> statement-breakpoint
CREATE INDEX "recovery_codes_user_status_idx" ON "recovery_codes" USING btree ("user_id","status");--> statement-breakpoint
CREATE INDEX "recovery_codes_org_user_idx" ON "recovery_codes" USING btree ("organization_id","user_id");