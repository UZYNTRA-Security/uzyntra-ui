ALTER TABLE "api_keys" DROP CONSTRAINT "api_keys_status_check";--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "service_account_id" uuid;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_service_account_id_service_accounts_id_fk" FOREIGN KEY ("service_account_id") REFERENCES "public"."service_accounts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "api_keys_service_account_id_idx" ON "api_keys" USING btree ("service_account_id");--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_status_check" CHECK ("api_keys"."status" in ('active', 'revoked', 'expired', 'disabled', 'deleted'));