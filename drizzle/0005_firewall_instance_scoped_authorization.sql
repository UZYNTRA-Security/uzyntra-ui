CREATE TABLE "firewall_instance_role_assignments" (
	"firewall_instance_id" uuid NOT NULL,
	"membership_id" uuid NOT NULL,
	"role_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "firewall_instance_role_assignments_firewall_instance_id_membership_id_role_id_pk" PRIMARY KEY("firewall_instance_id","membership_id","role_id")
);
--> statement-breakpoint
ALTER TABLE "firewall_instance_role_assignments" ADD CONSTRAINT "firewall_instance_role_assignments_firewall_instance_id_firewall_instances_id_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_instance_role_assignments" ADD CONSTRAINT "firewall_instance_role_assignments_membership_id_organization_memberships_id_fk" FOREIGN KEY ("membership_id") REFERENCES "public"."organization_memberships"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "firewall_instance_role_assignments" ADD CONSTRAINT "firewall_instance_role_assignments_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "firewall_instance_role_assignments_membership_id_idx" ON "firewall_instance_role_assignments" USING btree ("membership_id");--> statement-breakpoint
CREATE INDEX "firewall_instance_role_assignments_role_id_idx" ON "firewall_instance_role_assignments" USING btree ("role_id");