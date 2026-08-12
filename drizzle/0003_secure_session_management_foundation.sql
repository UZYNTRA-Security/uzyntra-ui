ALTER TABLE "sessions" ADD COLUMN "last_seen_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "ip_address" varchar(45);--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "user_agent" text;