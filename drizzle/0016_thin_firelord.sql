CREATE TABLE "oauth_login_attempts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_id" uuid NOT NULL,
	"state_hash" text NOT NULL,
	"pkce_verifier_hash" text NOT NULL,
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
	CONSTRAINT "oauth_login_attempts_status_chk" CHECK ("oauth_login_attempts"."status" in ('pending', 'completed', 'failed', 'expired'))
);
--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "scopes" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "authorization_endpoint" text;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "token_endpoint" text;--> statement-breakpoint
ALTER TABLE "identity_providers" ADD COLUMN "user_info_endpoint" text;--> statement-breakpoint
UPDATE "identity_providers"
SET
	"status" = 'active',
	"scopes" = ARRAY['openid', 'email', 'profile']::text[],
	"authorization_endpoint" = 'https://accounts.google.com/o/oauth2/v2/auth',
	"token_endpoint" = 'https://oauth2.googleapis.com/token',
	"user_info_endpoint" = 'https://openidconnect.googleapis.com/v1/userinfo',
	"updated_at" = now()
WHERE "provider_key" = 'google'
	AND "organization_id" IS NULL;--> statement-breakpoint
UPDATE "identity_providers"
SET
	"status" = 'active',
	"scopes" = ARRAY['read:user', 'user:email']::text[],
	"authorization_endpoint" = 'https://github.com/login/oauth/authorize',
	"token_endpoint" = 'https://github.com/login/oauth/access_token',
	"user_info_endpoint" = 'https://api.github.com/user',
	"updated_at" = now()
WHERE "provider_key" = 'github'
	AND "organization_id" IS NULL;--> statement-breakpoint
ALTER TABLE "oauth_login_attempts" ADD CONSTRAINT "oauth_login_attempts_provider_id_identity_providers_id_fk" FOREIGN KEY ("provider_id") REFERENCES "public"."identity_providers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "oauth_login_attempts_state_idx" ON "oauth_login_attempts" USING btree ("state_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "oauth_login_attempts_code_idx" ON "oauth_login_attempts" USING btree ("authorization_code_hash") WHERE authorization_code_hash IS NOT NULL;--> statement-breakpoint
CREATE INDEX "oauth_login_attempts_provider_status_idx" ON "oauth_login_attempts" USING btree ("provider_id","status");--> statement-breakpoint
CREATE INDEX "oauth_login_attempts_expires_idx" ON "oauth_login_attempts" USING btree ("expires_at");
