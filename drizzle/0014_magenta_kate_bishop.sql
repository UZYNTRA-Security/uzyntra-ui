CREATE TABLE "ai_analysis_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid,
	"session_id" uuid,
	"incident_id" uuid,
	"firewall_instance_id" uuid,
	"report_type" varchar(40) NOT NULL,
	"title" varchar(240) NOT NULL,
	"summary" text NOT NULL,
	"findings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"recommendations" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"guardrail_result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"provider" varchar(80) DEFAULT 'local_advisory' NOT NULL,
	"model" varchar(120) DEFAULT 'deterministic-summary' NOT NULL,
	"confidence" real DEFAULT 0.6 NOT NULL,
	"generated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ai_reports_type_chk" CHECK ("ai_analysis_reports"."report_type" in ('executive', 'analyst', 'compliance', 'incident_summary', 'customer_security')),
	CONSTRAINT "ai_reports_confidence_chk" CHECK ("ai_analysis_reports"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "ai_feedback" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"message_id" uuid,
	"report_id" uuid,
	"user_id" uuid NOT NULL,
	"rating" varchar(32) NOT NULL,
	"feedback" text,
	"reviewed_by_user_id" uuid,
	"reviewed_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ai_feedback_rating_chk" CHECK ("ai_feedback"."rating" in ('helpful', 'not_helpful', 'unsafe', 'incorrect', 'needs_detail')),
	CONSTRAINT "ai_feedback_target_chk" CHECK ("ai_feedback"."message_id" is not null or "ai_feedback"."report_id" is not null)
);
--> statement-breakpoint
CREATE TABLE "ai_messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"user_id" uuid,
	"role" varchar(24) NOT NULL,
	"content" text NOT NULL,
	"sanitized_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"guardrail_result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"provider" varchar(80) DEFAULT 'local_advisory' NOT NULL,
	"model" varchar(120) DEFAULT 'deterministic-summary' NOT NULL,
	"confidence" real DEFAULT 0.6 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ai_messages_role_chk" CHECK ("ai_messages"."role" in ('user', 'assistant', 'system')),
	CONSTRAINT "ai_messages_confidence_chk" CHECK ("ai_messages"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "ai_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"title" varchar(200) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"purpose" varchar(80) DEFAULT 'security_analysis' NOT NULL,
	"last_message_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "ai_sessions_status_chk" CHECK ("ai_sessions"."status" in ('active', 'archived', 'deleted'))
);
--> statement-breakpoint
CREATE TABLE "automation_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"playbook_id" uuid,
	"incident_id" uuid,
	"alert_id" uuid,
	"security_event_id" uuid,
	"detection_finding_id" uuid,
	"correlation_event_id" uuid,
	"threat_match_id" uuid,
	"policy_decision_id" uuid,
	"enforcement_event_id" uuid,
	"notification_delivery_id" uuid,
	"simulation_result_id" uuid,
	"trigger_type" varchar(40) NOT NULL,
	"trigger_fingerprint" varchar(64) NOT NULL,
	"status" varchar(32) DEFAULT 'queued' NOT NULL,
	"automation_level" integer DEFAULT 1 NOT NULL,
	"approval_state" varchar(32) DEFAULT 'not_required' NOT NULL,
	"idempotency_key" varchar(160) NOT NULL,
	"playbook_version" integer DEFAULT 1 NOT NULL,
	"started_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"result_summary" text,
	"failure_reason" text,
	"evidence_summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "automation_runs_trigger_chk" CHECK ("automation_runs"."trigger_type" in ('security_event', 'detection_finding', 'correlation_event', 'threat_match', 'policy_decision', 'enforcement_event', 'incident', 'notification_delivery', 'simulation_result', 'manual')),
	CONSTRAINT "automation_runs_status_chk" CHECK ("automation_runs"."status" in ('queued', 'running', 'approval_required', 'completed', 'failed', 'cancelled', 'skipped')),
	CONSTRAINT "automation_runs_level_chk" CHECK ("automation_runs"."automation_level" between 0 and 4),
	CONSTRAINT "automation_runs_approval_chk" CHECK ("automation_runs"."approval_state" in ('not_required', 'pending', 'approved', 'rejected', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "backup_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"region_id" uuid,
	"backup_type" varchar(40) DEFAULT 'database' NOT NULL,
	"status" varchar(32) DEFAULT 'scheduled' NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"rpo_minutes" integer DEFAULT 1440 NOT NULL,
	"retention_days" integer DEFAULT 30 NOT NULL,
	"storage_location_ref" varchar(160),
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "backup_jobs_status_chk" CHECK ("backup_jobs"."status" in ('scheduled', 'running', 'completed', 'failed', 'cancelled')),
	CONSTRAINT "backup_jobs_type_chk" CHECK ("backup_jobs"."backup_type" in ('database', 'event_archive', 'configuration', 'evidence_bundle')),
	CONSTRAINT "backup_jobs_rpo_chk" CHECK ("backup_jobs"."rpo_minutes" >= 0),
	CONSTRAINT "backup_jobs_retention_chk" CHECK ("backup_jobs"."retention_days" between 1 and 3650)
);
--> statement-breakpoint
CREATE TABLE "compliance_reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"requested_by_user_id" uuid,
	"report_type" varchar(48) NOT NULL,
	"framework" varchar(80) DEFAULT 'nist_csf' NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"title" varchar(240) NOT NULL,
	"period_start" timestamp with time zone NOT NULL,
	"period_end" timestamp with time zone NOT NULL,
	"summary" text NOT NULL,
	"evidence_refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"control_mappings" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"generated_ai_report_id" uuid,
	"published_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "compliance_reports_type_chk" CHECK ("compliance_reports"."report_type" in ('security_posture', 'incident_summary', 'compliance_summary', 'executive', 'customer_security')),
	CONSTRAINT "compliance_reports_status_chk" CHECK ("compliance_reports"."status" in ('draft', 'generated', 'review_required', 'published', 'archived')),
	CONSTRAINT "compliance_reports_period_chk" CHECK ("compliance_reports"."period_end" >= "compliance_reports"."period_start")
);
--> statement-breakpoint
CREATE TABLE "credential_protection_state" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"api_key_id" uuid,
	"credential_fingerprint" varchar(64) NOT NULL,
	"credential_label" varchar(160),
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"reason" text,
	"source_decision_id" uuid,
	"created_by_user_id" uuid,
	"released_by_user_id" uuid,
	"restricted_until" timestamp with time zone,
	"released_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "credential_protection_state_status_chk" CHECK ("credential_protection_state"."status" in ('active', 'suspicious', 'restricted', 'suspended', 'released'))
);
--> statement-breakpoint
CREATE TABLE "customer_contacts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"parent_organization_id" uuid,
	"contact_type" varchar(32) NOT NULL,
	"name" varchar(160) NOT NULL,
	"email" varchar(320) NOT NULL,
	"phone" varchar(64),
	"escalation_priority" integer DEFAULT 1 NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "customer_contacts_type_chk" CHECK ("customer_contacts"."contact_type" in ('security', 'billing', 'technical', 'executive', 'incident')),
	CONSTRAINT "customer_contacts_status_chk" CHECK ("customer_contacts"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "customer_contacts_escalation_priority_chk" CHECK ("customer_contacts"."escalation_priority" between 1 and 5)
);
--> statement-breakpoint
CREATE TABLE "delegated_access_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"provider_organization_id" uuid NOT NULL,
	"customer_organization_id" uuid NOT NULL,
	"user_id" uuid,
	"access_level" varchar(32) NOT NULL,
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"permissions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"approval_state" varchar(32) DEFAULT 'pending_customer_approval' NOT NULL,
	"justification" text,
	"expires_at" timestamp with time zone,
	"approved_by_user_id" uuid,
	"revoked_by_user_id" uuid,
	"revoked_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "delegated_access_level_chk" CHECK ("delegated_access_grants"."access_level" in ('viewer', 'analyst', 'responder', 'admin', 'auditor')),
	CONSTRAINT "delegated_access_status_chk" CHECK ("delegated_access_grants"."status" in ('active', 'pending', 'suspended', 'revoked', 'expired')),
	CONSTRAINT "delegated_access_distinct_orgs_chk" CHECK ("delegated_access_grants"."provider_organization_id" <> "delegated_access_grants"."customer_organization_id")
);
--> statement-breakpoint
CREATE TABLE "developer_apps" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"owner_user_id" uuid,
	"name" varchar(160) NOT NULL,
	"slug" varchar(120) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"app_type" varchar(48) DEFAULT 'api_consumer' NOT NULL,
	"callback_urls" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"allowed_scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"rate_limit_per_minute" integer DEFAULT 60 NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "developer_apps_status_chk" CHECK ("developer_apps"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "developer_apps_type_chk" CHECK ("developer_apps"."app_type" in ('api_consumer', 'webhook_app', 'partner_integration', 'internal_tool')),
	CONSTRAINT "developer_apps_rate_limit_chk" CHECK ("developer_apps"."rate_limit_per_minute" between 1 and 100000)
);
--> statement-breakpoint
CREATE TABLE "emergency_bypasses" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"reason" text NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"created_by_user_id" uuid,
	"revoked_by_user_id" uuid,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "emergency_bypasses_status_chk" CHECK ("emergency_bypasses"."status" in ('active', 'expired', 'revoked')),
	CONSTRAINT "emergency_bypasses_expiry_chk" CHECK ("emergency_bypasses"."expires_at" > "emergency_bypasses"."created_at")
);
--> statement-breakpoint
CREATE TABLE "enforcement_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"policy_decision_id" uuid,
	"policy_id" uuid,
	"policy_version_id" uuid,
	"protection_rule_id" uuid,
	"rate_limit_policy_id" uuid,
	"credential_protection_state_id" uuid,
	"alert_id" uuid,
	"incident_id" uuid,
	"action" varchar(32) NOT NULL,
	"mode" varchar(32) NOT NULL,
	"outcome" varchar(32) NOT NULL,
	"reason" varchar(240) NOT NULL,
	"risk_score" real DEFAULT 0 NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"detector_references" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"enforcement_key_hash" varchar(64),
	"expires_at" timestamp with time zone,
	"request_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"explanation" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "enforcement_events_action_chk" CHECK ("enforcement_events"."action" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')),
	CONSTRAINT "enforcement_events_mode_chk" CHECK ("enforcement_events"."mode" in ('observe', 'simulation', 'enforcement')),
	CONSTRAINT "enforcement_events_outcome_chk" CHECK ("enforcement_events"."outcome" in ('observed', 'simulated', 'applied', 'failed', 'bypassed')),
	CONSTRAINT "enforcement_events_risk_score_chk" CHECK ("enforcement_events"."risk_score" between 0 and 100),
	CONSTRAINT "enforcement_events_confidence_chk" CHECK ("enforcement_events"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "evidence_items" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"investigation_case_id" uuid,
	"incident_id" uuid,
	"automation_run_id" uuid,
	"response_action_id" uuid,
	"source_type" varchar(48) NOT NULL,
	"source_ref_id" uuid,
	"evidence_type" varchar(80) NOT NULL,
	"evidence_hash" varchar(64) NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"collected_by_user_id" uuid,
	"retention_class" varchar(40) DEFAULT 'incident_1y' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "evidence_items_source_type_chk" CHECK ("evidence_items"."source_type" in ('security_event', 'detection_finding', 'correlation_event', 'threat_match', 'policy_decision', 'enforcement_event', 'incident', 'notification_delivery', 'simulation_result', 'automation_run', 'response_action', 'manual')),
	CONSTRAINT "evidence_items_retention_chk" CHECK ("evidence_items"."retention_class" in ('incident_90d', 'incident_1y', 'audit_1y', 'customer_policy'))
);
--> statement-breakpoint
CREATE TABLE "integration_catalog" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"publisher_organization_id" uuid,
	"name" varchar(160) NOT NULL,
	"slug" varchar(120) NOT NULL,
	"category" varchar(48) NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"capability_manifest" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"permission_manifest" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"security_review_status" varchar(40) DEFAULT 'not_started' NOT NULL,
	"version" varchar(40) DEFAULT '0.1.0' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "integration_catalog_category_chk" CHECK ("integration_catalog"."category" in ('siem', 'soar', 'ticketing', 'identity', 'cloud', 'notification', 'threat_intelligence', 'compliance', 'developer')),
	CONSTRAINT "integration_catalog_status_chk" CHECK ("integration_catalog"."status" in ('draft', 'review', 'active', 'deprecated', 'disabled')),
	CONSTRAINT "integration_catalog_security_review_chk" CHECK ("integration_catalog"."security_review_status" in ('not_started', 'in_review', 'approved', 'rejected', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "investigation_cases" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"incident_id" uuid,
	"automation_run_id" uuid,
	"title" varchar(240) NOT NULL,
	"summary" text,
	"severity" varchar(32) DEFAULT 'medium' NOT NULL,
	"status" varchar(32) DEFAULT 'open' NOT NULL,
	"assigned_to_user_id" uuid,
	"created_by_user_id" uuid,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sla_due_at" timestamp with time zone,
	"resolved_at" timestamp with time zone,
	"resolution" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "investigation_cases_status_chk" CHECK ("investigation_cases"."status" in ('open', 'investigating', 'contained', 'resolved', 'closed')),
	CONSTRAINT "investigation_cases_severity_chk" CHECK ("investigation_cases"."severity" in ('low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
CREATE TABLE "marketplace_listings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"integration_id" uuid NOT NULL,
	"publisher_organization_id" uuid,
	"name" varchar(160) NOT NULL,
	"category" varchar(48) NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"summary" text NOT NULL,
	"capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"pricing_model" varchar(48) DEFAULT 'bring_your_own_license' NOT NULL,
	"security_review_status" varchar(40) DEFAULT 'not_started' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "marketplace_listings_category_chk" CHECK ("marketplace_listings"."category" in ('siem', 'soar', 'ticketing', 'identity', 'cloud', 'notification', 'threat_intelligence', 'compliance', 'developer')),
	CONSTRAINT "marketplace_listings_status_chk" CHECK ("marketplace_listings"."status" in ('draft', 'review', 'published', 'suspended', 'retired')),
	CONSTRAINT "marketplace_listings_security_review_chk" CHECK ("marketplace_listings"."security_review_status" in ('not_started', 'in_review', 'approved', 'rejected', 'expired'))
);
--> statement-breakpoint
CREATE TABLE "organization_hierarchy" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"parent_organization_id" uuid NOT NULL,
	"child_organization_id" uuid NOT NULL,
	"relationship_type" varchar(40) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"delegation_mode" varchar(40) DEFAULT 'explicit' NOT NULL,
	"created_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"approved_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "organization_hierarchy_type_chk" CHECK ("organization_hierarchy"."relationship_type" in ('mssp_customer', 'enterprise_child', 'business_unit', 'subsidiary')),
	CONSTRAINT "organization_hierarchy_status_chk" CHECK ("organization_hierarchy"."status" in ('active', 'pending', 'suspended', 'revoked', 'expired')),
	CONSTRAINT "organization_hierarchy_no_self_parent_chk" CHECK ("organization_hierarchy"."parent_organization_id" <> "organization_hierarchy"."child_organization_id")
);
--> statement-breakpoint
CREATE TABLE "platform_health_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid,
	"region_id" uuid,
	"service_id" uuid,
	"service_type" varchar(48) NOT NULL,
	"status" varchar(32) NOT NULL,
	"availability_percent" real DEFAULT 100 NOT NULL,
	"latency_p95_ms" integer DEFAULT 0 NOT NULL,
	"error_rate_percent" real DEFAULT 0 NOT NULL,
	"checked_at" timestamp with time zone DEFAULT now() NOT NULL,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_health_service_type_chk" CHECK ("platform_health_records"."service_type" in ('control_plane', 'gateway', 'database', 'ingestion', 'notification', 'ai', 'marketplace', 'developer_api')),
	CONSTRAINT "platform_health_status_chk" CHECK ("platform_health_records"."status" in ('healthy', 'degraded', 'down', 'maintenance', 'unknown')),
	CONSTRAINT "platform_health_availability_chk" CHECK ("platform_health_records"."availability_percent" between 0 and 100),
	CONSTRAINT "platform_health_latency_chk" CHECK ("platform_health_records"."latency_p95_ms" >= 0),
	CONSTRAINT "platform_health_error_rate_chk" CHECK ("platform_health_records"."error_rate_percent" between 0 and 100)
);
--> statement-breakpoint
CREATE TABLE "platform_regions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"region_key" varchar(80) NOT NULL,
	"name" varchar(160) NOT NULL,
	"geography" varchar(120) NOT NULL,
	"provider" varchar(80) DEFAULT 'multi_provider' NOT NULL,
	"status" varchar(32) DEFAULT 'planned' NOT NULL,
	"data_residency_class" varchar(80) DEFAULT 'standard' NOT NULL,
	"primary_control_plane" boolean DEFAULT false NOT NULL,
	"failover_allowed" boolean DEFAULT false NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "platform_regions_status_chk" CHECK ("platform_regions"."status" in ('planned', 'active', 'degraded', 'maintenance', 'retired'))
);
--> statement-breakpoint
CREATE TABLE "playbook_steps" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"playbook_id" uuid NOT NULL,
	"step_order" integer DEFAULT 1 NOT NULL,
	"name" varchar(160) NOT NULL,
	"action_type" varchar(48) NOT NULL,
	"approval_required" boolean DEFAULT false NOT NULL,
	"configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"rollback_configuration" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"timeout_seconds" integer DEFAULT 30 NOT NULL,
	"max_attempts" integer DEFAULT 1 NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "playbook_steps_status_chk" CHECK ("playbook_steps"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "playbook_steps_action_chk" CHECK ("playbook_steps"."action_type" in ('block_indicator', 'create_incident', 'notify_security_team', 'request_approval', 'collect_evidence', 'quarantine_api_key', 'suspend_service_account', 'increase_rate_limit_restriction')),
	CONSTRAINT "playbook_steps_order_chk" CHECK ("playbook_steps"."step_order" between 1 and 100),
	CONSTRAINT "playbook_steps_attempts_chk" CHECK ("playbook_steps"."max_attempts" between 1 and 10 and "playbook_steps"."timeout_seconds" between 1 and 3600)
);
--> statement-breakpoint
CREATE TABLE "policy_change_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"policy_id" uuid NOT NULL,
	"policy_version_id" uuid,
	"simulation_id" uuid,
	"requested_action" varchar(32) NOT NULL,
	"status" varchar(32) DEFAULT 'requested' NOT NULL,
	"reason" text NOT NULL,
	"reviewer_user_id" uuid,
	"requested_by_user_id" uuid,
	"decided_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"decision_note" text,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "policy_change_requests_status_chk" CHECK ("policy_change_requests"."status" in ('draft', 'requested', 'approved', 'rejected', 'expired', 'cancelled')),
	CONSTRAINT "policy_change_requests_action_chk" CHECK ("policy_change_requests"."requested_action" in ('create', 'update', 'activate', 'rollback', 'promote_to_enforce')),
	CONSTRAINT "policy_change_requests_expiry_chk" CHECK ("policy_change_requests"."expires_at" is null or "policy_change_requests"."expires_at" > "policy_change_requests"."created_at")
);
--> statement-breakpoint
CREATE TABLE "policy_decisions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"security_event_id" uuid,
	"policy_id" uuid,
	"policy_version_id" uuid,
	"correlation_event_id" uuid,
	"alert_id" uuid,
	"incident_id" uuid,
	"decision" varchar(32) NOT NULL,
	"decision_reason" varchar(240) NOT NULL,
	"mode" varchar(32) DEFAULT 'observe' NOT NULL,
	"fail_behavior" varchar(32) DEFAULT 'fail_open' NOT NULL,
	"risk_score" real DEFAULT 0 NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"identity_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"request_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"detector_references" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"threat_intel_references" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"enforcement_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"explanation" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"evaluated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "policy_decisions_decision_chk" CHECK ("policy_decisions"."decision" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine')),
	CONSTRAINT "policy_decisions_mode_chk" CHECK ("policy_decisions"."mode" in ('observe', 'simulate', 'enforce')),
	CONSTRAINT "policy_decisions_fail_behavior_chk" CHECK ("policy_decisions"."fail_behavior" in ('fail_open', 'fail_closed')),
	CONSTRAINT "policy_decisions_risk_score_chk" CHECK ("policy_decisions"."risk_score" between 0 and 100),
	CONSTRAINT "policy_decisions_confidence_chk" CHECK ("policy_decisions"."confidence" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "policy_simulations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"policy_id" uuid,
	"policy_version_id" uuid,
	"source_security_event_id" uuid,
	"source_policy_decision_id" uuid,
	"source_enforcement_event_id" uuid,
	"mode" varchar(32) NOT NULL,
	"status" varchar(32) DEFAULT 'completed' NOT NULL,
	"input_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"simulation_config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"impact_summary" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"summary" text,
	"error_message" text,
	"created_by_user_id" uuid,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "policy_simulations_mode_chk" CHECK ("policy_simulations"."mode" in ('dry_run', 'shadow', 'what_if', 'historical_replay')),
	CONSTRAINT "policy_simulations_status_chk" CHECK ("policy_simulations"."status" in ('queued', 'running', 'completed', 'failed', 'cancelled'))
);
--> statement-breakpoint
CREATE TABLE "policy_test_cases" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"policy_id" uuid,
	"policy_version_id" uuid,
	"name" varchar(160) NOT NULL,
	"description" text,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"input_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"expected_decision" varchar(32) NOT NULL,
	"expected_action" varchar(32) NOT NULL,
	"last_result" varchar(32),
	"last_run_at" timestamp with time zone,
	"created_by_user_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "policy_test_cases_status_chk" CHECK ("policy_test_cases"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "policy_test_cases_decision_chk" CHECK ("policy_test_cases"."expected_decision" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine')),
	CONSTRAINT "policy_test_cases_action_chk" CHECK ("policy_test_cases"."expected_action" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')),
	CONSTRAINT "policy_test_cases_last_result_chk" CHECK ("policy_test_cases"."last_result" is null or "policy_test_cases"."last_result" in ('passed', 'failed'))
);
--> statement-breakpoint
CREATE TABLE "protection_allowlists" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"entry_type" varchar(32) NOT NULL,
	"entry_hash" varchar(64) NOT NULL,
	"entry_label" varchar(240) NOT NULL,
	"reason" text NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"created_by_user_id" uuid,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "protection_allowlists_status_chk" CHECK ("protection_allowlists"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "protection_allowlists_type_chk" CHECK ("protection_allowlists"."entry_type" in ('ip', 'cidr', 'route', 'credential', 'detector', 'indicator'))
);
--> statement-breakpoint
CREATE TABLE "protection_blocklists" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"entry_type" varchar(32) NOT NULL,
	"entry_hash" varchar(64) NOT NULL,
	"entry_label" varchar(240) NOT NULL,
	"reason" text NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"source_decision_id" uuid,
	"created_by_user_id" uuid,
	"expires_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "protection_blocklists_status_chk" CHECK ("protection_blocklists"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "protection_blocklists_type_chk" CHECK ("protection_blocklists"."entry_type" in ('ip', 'cidr', 'route', 'credential', 'detector', 'indicator'))
);
--> statement-breakpoint
CREATE TABLE "protection_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"name" varchar(160) NOT NULL,
	"description" text,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"mode" varchar(32) DEFAULT 'observe' NOT NULL,
	"action" varchar(32) NOT NULL,
	"precedence" integer DEFAULT 500 NOT NULL,
	"conditions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"ttl_seconds" integer,
	"rate_limit_policy_id" uuid,
	"created_by_user_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "protection_rules_status_chk" CHECK ("protection_rules"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "protection_rules_mode_chk" CHECK ("protection_rules"."mode" in ('observe', 'simulation', 'enforcement')),
	CONSTRAINT "protection_rules_action_chk" CHECK ("protection_rules"."action" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')),
	CONSTRAINT "protection_rules_precedence_chk" CHECK ("protection_rules"."precedence" between 1 and 10000),
	CONSTRAINT "protection_rules_ttl_chk" CHECK ("protection_rules"."ttl_seconds" is null or "protection_rules"."ttl_seconds" between 60 and 2592000)
);
--> statement-breakpoint
CREATE TABLE "rate_limit_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"dimension" varchar(32) DEFAULT 'source' NOT NULL,
	"limit_count" integer NOT NULL,
	"window_seconds" integer NOT NULL,
	"burst_count" integer,
	"created_by_user_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "rate_limit_policies_status_chk" CHECK ("rate_limit_policies"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "rate_limit_policies_dimension_chk" CHECK ("rate_limit_policies"."dimension" in ('organization', 'firewall', 'route', 'credential', 'source')),
	CONSTRAINT "rate_limit_policies_limit_chk" CHECK ("rate_limit_policies"."limit_count" between 1 and 100000),
	CONSTRAINT "rate_limit_policies_window_chk" CHECK ("rate_limit_policies"."window_seconds" between 10 and 86400),
	CONSTRAINT "rate_limit_policies_burst_chk" CHECK ("rate_limit_policies"."burst_count" is null or "rate_limit_policies"."burst_count" between 1 and 100000)
);
--> statement-breakpoint
CREATE TABLE "rate_limit_state" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"rate_limit_policy_id" uuid NOT NULL,
	"dimension" varchar(32) NOT NULL,
	"key_hash" varchar(64) NOT NULL,
	"key_label" varchar(240),
	"count" integer DEFAULT 0 NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "rate_limit_state_count_chk" CHECK ("rate_limit_state"."count" >= 0),
	CONSTRAINT "rate_limit_state_window_chk" CHECK ("rate_limit_state"."window_end" > "rate_limit_state"."window_start")
);
--> statement-breakpoint
CREATE TABLE "recovery_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"region_id" uuid,
	"backup_job_id" uuid,
	"restore_operation_id" uuid,
	"event_type" varchar(48) NOT NULL,
	"severity" varchar(32) DEFAULT 'info' NOT NULL,
	"summary" text NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "recovery_events_type_chk" CHECK ("recovery_events"."event_type" in ('backup_completed', 'backup_failed', 'restore_requested', 'restore_completed', 'failover_started', 'failover_completed', 'region_degraded', 'region_recovered')),
	CONSTRAINT "recovery_events_severity_chk" CHECK ("recovery_events"."severity" in ('info', 'low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
CREATE TABLE "regional_services" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"region_id" uuid NOT NULL,
	"organization_id" uuid,
	"service_type" varchar(48) NOT NULL,
	"name" varchar(160) NOT NULL,
	"provider" varchar(80) DEFAULT 'unknown' NOT NULL,
	"status" varchar(32) DEFAULT 'planned' NOT NULL,
	"endpoint_host" varchar(255),
	"health_check_path" varchar(160) DEFAULT '/healthz' NOT NULL,
	"last_healthy_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "regional_services_type_chk" CHECK ("regional_services"."service_type" in ('control_plane', 'gateway', 'database', 'ingestion', 'notification', 'ai', 'marketplace', 'developer_api')),
	CONSTRAINT "regional_services_status_chk" CHECK ("regional_services"."status" in ('planned', 'active', 'degraded', 'maintenance', 'failed', 'retired'))
);
--> statement-breakpoint
CREATE TABLE "residency_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"home_region_id" uuid NOT NULL,
	"policy_name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"allowed_region_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"restricted_data_classes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"cross_region_export_allowed" boolean DEFAULT false NOT NULL,
	"ai_processing_region_locked" boolean DEFAULT true NOT NULL,
	"approved_by_user_id" uuid,
	"approved_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "residency_policies_status_chk" CHECK ("residency_policies"."status" in ('active', 'draft', 'disabled', 'retired'))
);
--> statement-breakpoint
CREATE TABLE "response_actions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"automation_run_id" uuid,
	"playbook_step_id" uuid,
	"incident_id" uuid,
	"policy_decision_id" uuid,
	"enforcement_event_id" uuid,
	"action_type" varchar(48) NOT NULL,
	"target_type" varchar(80),
	"target_ref" varchar(240),
	"status" varchar(32) DEFAULT 'pending' NOT NULL,
	"approval_state" varchar(32) DEFAULT 'not_required' NOT NULL,
	"risk_level" varchar(32) DEFAULT 'medium' NOT NULL,
	"idempotency_key" varchar(160) NOT NULL,
	"reason" text NOT NULL,
	"requested_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"executed_by_user_id" uuid,
	"execution_result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"rollback_plan" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"rollback_state" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"error_message" text,
	"executed_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "response_actions_type_chk" CHECK ("response_actions"."action_type" in ('block_indicator', 'create_incident', 'notify_security_team', 'request_approval', 'collect_evidence', 'quarantine_api_key', 'suspend_service_account', 'increase_rate_limit_restriction')),
	CONSTRAINT "response_actions_status_chk" CHECK ("response_actions"."status" in ('recommended', 'pending', 'approval_required', 'approved', 'executing', 'completed', 'failed', 'skipped', 'rolled_back')),
	CONSTRAINT "response_actions_approval_chk" CHECK ("response_actions"."approval_state" in ('not_required', 'pending', 'approved', 'rejected', 'expired')),
	CONSTRAINT "response_actions_risk_chk" CHECK ("response_actions"."risk_level" in ('low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
CREATE TABLE "restore_operations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"backup_job_id" uuid,
	"target_region_id" uuid,
	"status" varchar(32) DEFAULT 'requested' NOT NULL,
	"requested_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"validation_result" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "restore_operations_status_chk" CHECK ("restore_operations"."status" in ('requested', 'approved', 'running', 'completed', 'failed', 'cancelled'))
);
--> statement-breakpoint
CREATE TABLE "security_playbooks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"name" varchar(160) NOT NULL,
	"description" text,
	"trigger_type" varchar(40) NOT NULL,
	"trigger_conditions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"automation_level" integer DEFAULT 1 NOT NULL,
	"risk_level" varchar(32) DEFAULT 'medium' NOT NULL,
	"requires_approval" boolean DEFAULT true NOT NULL,
	"action_sequence" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"rollback_plan" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"max_runs_per_hour" integer DEFAULT 20 NOT NULL,
	"cooldown_seconds" integer DEFAULT 300 NOT NULL,
	"created_by_user_id" uuid,
	"approved_by_user_id" uuid,
	"approved_at" timestamp with time zone,
	"last_run_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "security_playbooks_status_chk" CHECK ("security_playbooks"."status" in ('draft', 'testing', 'active', 'disabled', 'deleted')),
	CONSTRAINT "security_playbooks_trigger_chk" CHECK ("security_playbooks"."trigger_type" in ('security_event', 'detection_finding', 'correlation_event', 'threat_match', 'policy_decision', 'enforcement_event', 'incident', 'notification_delivery', 'simulation_result', 'manual')),
	CONSTRAINT "security_playbooks_level_chk" CHECK ("security_playbooks"."automation_level" between 0 and 4),
	CONSTRAINT "security_playbooks_risk_chk" CHECK ("security_playbooks"."risk_level" in ('low', 'medium', 'high', 'critical')),
	CONSTRAINT "security_playbooks_version_chk" CHECK ("security_playbooks"."version" >= 1),
	CONSTRAINT "security_playbooks_budget_chk" CHECK ("security_playbooks"."max_runs_per_hour" between 1 and 500 and "security_playbooks"."cooldown_seconds" between 0 and 86400)
);
--> statement-breakpoint
CREATE TABLE "simulation_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"simulation_id" uuid NOT NULL,
	"policy_id" uuid,
	"policy_version_id" uuid,
	"policy_decision_id" uuid,
	"enforcement_event_id" uuid,
	"expected_decision" varchar(32) NOT NULL,
	"expected_action" varchar(32) NOT NULL,
	"actual_action" varchar(32),
	"risk_score" real DEFAULT 0 NOT NULL,
	"confidence" real DEFAULT 0 NOT NULL,
	"matched_policy_rule_id" varchar(160),
	"matched_protection_rule_id" uuid,
	"reason_codes" text[] DEFAULT ARRAY[]::text[] NOT NULL,
	"explanation" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"regression_status" varchar(32) DEFAULT 'not_applicable' NOT NULL,
	"false_positive_risk" real DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "simulation_results_decision_chk" CHECK ("simulation_results"."expected_decision" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine')),
	CONSTRAINT "simulation_results_expected_action_chk" CHECK ("simulation_results"."expected_action" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')),
	CONSTRAINT "simulation_results_actual_action_chk" CHECK ("simulation_results"."actual_action" is null or "simulation_results"."actual_action" in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')),
	CONSTRAINT "simulation_results_regression_status_chk" CHECK ("simulation_results"."regression_status" in ('not_applicable', 'passed', 'failed')),
	CONSTRAINT "simulation_results_risk_score_chk" CHECK ("simulation_results"."risk_score" between 0 and 100),
	CONSTRAINT "simulation_results_confidence_chk" CHECK ("simulation_results"."confidence" between 0 and 1),
	CONSTRAINT "simulation_results_false_positive_chk" CHECK ("simulation_results"."false_positive_risk" between 0 and 1)
);
--> statement-breakpoint
CREATE TABLE "tenant_region_assignments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"region_id" uuid NOT NULL,
	"assignment_type" varchar(40) DEFAULT 'home' NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"routing_priority" integer DEFAULT 100 NOT NULL,
	"residency_locked" boolean DEFAULT true NOT NULL,
	"failover_region_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"assigned_by_user_id" uuid,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_region_assignments_type_chk" CHECK ("tenant_region_assignments"."assignment_type" in ('home', 'failover', 'processing', 'archive')),
	CONSTRAINT "tenant_region_assignments_status_chk" CHECK ("tenant_region_assignments"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "tenant_region_assignments_priority_chk" CHECK ("tenant_region_assignments"."routing_priority" between 1 and 1000)
);
--> statement-breakpoint
CREATE TABLE "tenant_settings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"plan_key" varchar(40) DEFAULT 'starter' NOT NULL,
	"lifecycle_status" varchar(40) DEFAULT 'provisioning' NOT NULL,
	"data_residency" varchar(80) DEFAULT 'global' NOT NULL,
	"retention_days" integer DEFAULT 90 NOT NULL,
	"mssp_enabled" boolean DEFAULT false NOT NULL,
	"delegated_access_requires_approval" boolean DEFAULT true NOT NULL,
	"max_firewalls" integer DEFAULT 5 NOT NULL,
	"max_users" integer DEFAULT 10 NOT NULL,
	"features" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_settings_plan_chk" CHECK ("tenant_settings"."plan_key" in ('starter', 'professional', 'enterprise', 'mssp')),
	CONSTRAINT "tenant_settings_lifecycle_chk" CHECK ("tenant_settings"."lifecycle_status" in ('provisioning', 'active', 'suspended', 'pending_deletion', 'deleted', 'archived')),
	CONSTRAINT "tenant_settings_retention_days_chk" CHECK ("tenant_settings"."retention_days" between 7 and 2555),
	CONSTRAINT "tenant_settings_max_firewalls_chk" CHECK ("tenant_settings"."max_firewalls" >= 0),
	CONSTRAINT "tenant_settings_max_users_chk" CHECK ("tenant_settings"."max_users" >= 0)
);
--> statement-breakpoint
CREATE TABLE "usage_records" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"metric_type" varchar(64) NOT NULL,
	"quantity" integer DEFAULT 0 NOT NULL,
	"period_start" timestamp with time zone NOT NULL,
	"period_end" timestamp with time zone NOT NULL,
	"source" varchar(80) DEFAULT 'system' NOT NULL,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "usage_records_metric_type_chk" CHECK ("usage_records"."metric_type" in ('api_requests', 'security_events', 'alerts', 'incidents', 'firewall_instances', 'api_routes', 'notification_deliveries', 'ai_investigations', 'customer_tenants', 'analyst_seats')),
	CONSTRAINT "usage_records_quantity_chk" CHECK ("usage_records"."quantity" >= 0),
	CONSTRAINT "usage_records_period_chk" CHECK ("usage_records"."period_end" >= "usage_records"."period_start")
);
--> statement-breakpoint
CREATE TABLE "webhook_subscriptions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"developer_app_id" uuid,
	"integration_id" uuid,
	"name" varchar(160) NOT NULL,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"event_types" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"endpoint_host" varchar(255) NOT NULL,
	"signing_key_ref" varchar(160),
	"retry_policy" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_delivery_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "webhook_subscriptions_status_chk" CHECK ("webhook_subscriptions"."status" in ('active', 'disabled', 'paused', 'deleted'))
);
--> statement-breakpoint
CREATE TABLE "zero_trust_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"firewall_instance_id" uuid,
	"name" varchar(160) NOT NULL,
	"description" text,
	"status" varchar(32) DEFAULT 'active' NOT NULL,
	"mode" varchar(32) DEFAULT 'observe' NOT NULL,
	"fail_behavior" varchar(32) DEFAULT 'fail_open' NOT NULL,
	"active_version_id" uuid,
	"created_by_user_id" uuid,
	"activated_at" timestamp with time zone,
	"deactivated_at" timestamp with time zone,
	"metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone,
	CONSTRAINT "zero_trust_policies_status_chk" CHECK ("zero_trust_policies"."status" in ('active', 'disabled', 'deleted')),
	CONSTRAINT "zero_trust_policies_mode_chk" CHECK ("zero_trust_policies"."mode" in ('observe', 'simulate', 'enforce')),
	CONSTRAINT "zero_trust_policies_fail_behavior_chk" CHECK ("zero_trust_policies"."fail_behavior" in ('fail_open', 'fail_closed'))
);
--> statement-breakpoint
CREATE TABLE "zero_trust_policy_versions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"version_number" integer NOT NULL,
	"previous_version_id" uuid,
	"rollback_from_version_id" uuid,
	"status" varchar(32) DEFAULT 'draft' NOT NULL,
	"policy_snapshot" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"policy_digest" varchar(64) NOT NULL,
	"created_by_user_id" uuid,
	"activated_at" timestamp with time zone,
	"retired_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "zero_trust_policy_versions_status_chk" CHECK ("zero_trust_policy_versions"."status" in ('draft', 'active', 'retired', 'rolled_back')),
	CONSTRAINT "zero_trust_policy_versions_number_chk" CHECK ("zero_trust_policy_versions"."version_number" >= 1)
);
--> statement-breakpoint
ALTER TABLE "ai_analysis_reports" ADD CONSTRAINT "ai_reports_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analysis_reports" ADD CONSTRAINT "ai_reports_user_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analysis_reports" ADD CONSTRAINT "ai_reports_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."ai_sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analysis_reports" ADD CONSTRAINT "ai_reports_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_analysis_reports" ADD CONSTRAINT "ai_reports_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_feedback" ADD CONSTRAINT "ai_feedback_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_feedback" ADD CONSTRAINT "ai_feedback_message_fk" FOREIGN KEY ("message_id") REFERENCES "public"."ai_messages"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_feedback" ADD CONSTRAINT "ai_feedback_report_fk" FOREIGN KEY ("report_id") REFERENCES "public"."ai_analysis_reports"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_feedback" ADD CONSTRAINT "ai_feedback_user_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_feedback" ADD CONSTRAINT "ai_feedback_reviewed_by_fk" FOREIGN KEY ("reviewed_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_messages" ADD CONSTRAINT "ai_messages_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_messages" ADD CONSTRAINT "ai_messages_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."ai_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_messages" ADD CONSTRAINT "ai_messages_user_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_sessions" ADD CONSTRAINT "ai_sessions_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_sessions" ADD CONSTRAINT "ai_sessions_user_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ai_sessions" ADD CONSTRAINT "ai_sessions_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_playbook_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."security_playbooks"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_alert_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_security_event_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_detection_fk" FOREIGN KEY ("detection_finding_id") REFERENCES "public"."detection_findings"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_correlation_fk" FOREIGN KEY ("correlation_event_id") REFERENCES "public"."correlation_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_threat_match_fk" FOREIGN KEY ("threat_match_id") REFERENCES "public"."threat_matches"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_decision_fk" FOREIGN KEY ("policy_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_enforcement_fk" FOREIGN KEY ("enforcement_event_id") REFERENCES "public"."enforcement_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_delivery_fk" FOREIGN KEY ("notification_delivery_id") REFERENCES "public"."notification_deliveries"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_sim_result_fk" FOREIGN KEY ("simulation_result_id") REFERENCES "public"."simulation_results"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_started_by_fk" FOREIGN KEY ("started_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "automation_runs" ADD CONSTRAINT "automation_runs_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_jobs" ADD CONSTRAINT "backup_jobs_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "backup_jobs" ADD CONSTRAINT "backup_jobs_region_fk" FOREIGN KEY ("region_id") REFERENCES "public"."platform_regions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_requested_by_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "compliance_reports" ADD CONSTRAINT "compliance_reports_ai_report_fk" FOREIGN KEY ("generated_ai_report_id") REFERENCES "public"."ai_analysis_reports"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_api_key_fk" FOREIGN KEY ("api_key_id") REFERENCES "public"."api_keys"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_decision_fk" FOREIGN KEY ("source_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credential_protection_state" ADD CONSTRAINT "credential_protection_state_released_by_fk" FOREIGN KEY ("released_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_contacts" ADD CONSTRAINT "customer_contacts_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "customer_contacts" ADD CONSTRAINT "customer_contacts_parent_fk" FOREIGN KEY ("parent_organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegated_access_grants" ADD CONSTRAINT "delegated_access_provider_fk" FOREIGN KEY ("provider_organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegated_access_grants" ADD CONSTRAINT "delegated_access_customer_fk" FOREIGN KEY ("customer_organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegated_access_grants" ADD CONSTRAINT "delegated_access_user_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegated_access_grants" ADD CONSTRAINT "delegated_access_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "delegated_access_grants" ADD CONSTRAINT "delegated_access_revoked_by_fk" FOREIGN KEY ("revoked_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "developer_apps" ADD CONSTRAINT "developer_apps_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "developer_apps" ADD CONSTRAINT "developer_apps_owner_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "emergency_bypasses" ADD CONSTRAINT "emergency_bypasses_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "emergency_bypasses" ADD CONSTRAINT "emergency_bypasses_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "emergency_bypasses" ADD CONSTRAINT "emergency_bypasses_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "emergency_bypasses" ADD CONSTRAINT "emergency_bypasses_revoked_by_fk" FOREIGN KEY ("revoked_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_decision_fk" FOREIGN KEY ("policy_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_rule_fk" FOREIGN KEY ("protection_rule_id") REFERENCES "public"."protection_rules"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_rate_limit_fk" FOREIGN KEY ("rate_limit_policy_id") REFERENCES "public"."rate_limit_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_credential_state_fk" FOREIGN KEY ("credential_protection_state_id") REFERENCES "public"."credential_protection_state"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_alert_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "enforcement_events" ADD CONSTRAINT "enforcement_events_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_case_fk" FOREIGN KEY ("investigation_case_id") REFERENCES "public"."investigation_cases"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_run_fk" FOREIGN KEY ("automation_run_id") REFERENCES "public"."automation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_action_fk" FOREIGN KEY ("response_action_id") REFERENCES "public"."response_actions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "evidence_items" ADD CONSTRAINT "evidence_items_collected_by_fk" FOREIGN KEY ("collected_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_catalog" ADD CONSTRAINT "integration_catalog_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "integration_catalog" ADD CONSTRAINT "integration_catalog_publisher_fk" FOREIGN KEY ("publisher_organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_run_fk" FOREIGN KEY ("automation_run_id") REFERENCES "public"."automation_runs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_assigned_user_fk" FOREIGN KEY ("assigned_to_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "investigation_cases" ADD CONSTRAINT "investigation_cases_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "marketplace_listings" ADD CONSTRAINT "marketplace_listings_integration_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integration_catalog"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "marketplace_listings" ADD CONSTRAINT "marketplace_listings_publisher_fk" FOREIGN KEY ("publisher_organization_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_hierarchy" ADD CONSTRAINT "organization_hierarchy_parent_fk" FOREIGN KEY ("parent_organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_hierarchy" ADD CONSTRAINT "organization_hierarchy_child_fk" FOREIGN KEY ("child_organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_hierarchy" ADD CONSTRAINT "organization_hierarchy_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "organization_hierarchy" ADD CONSTRAINT "organization_hierarchy_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_health_records" ADD CONSTRAINT "platform_health_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_health_records" ADD CONSTRAINT "platform_health_region_fk" FOREIGN KEY ("region_id") REFERENCES "public"."platform_regions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "platform_health_records" ADD CONSTRAINT "platform_health_service_fk" FOREIGN KEY ("service_id") REFERENCES "public"."regional_services"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_steps" ADD CONSTRAINT "playbook_steps_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "playbook_steps" ADD CONSTRAINT "playbook_steps_playbook_fk" FOREIGN KEY ("playbook_id") REFERENCES "public"."security_playbooks"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_simulation_fk" FOREIGN KEY ("simulation_id") REFERENCES "public"."policy_simulations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_reviewer_fk" FOREIGN KEY ("reviewer_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_change_requests" ADD CONSTRAINT "policy_change_requests_requested_by_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_security_event_fk" FOREIGN KEY ("security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_decisions" ADD CONSTRAINT "policy_decisions_correlation_fk" FOREIGN KEY ("correlation_event_id") REFERENCES "public"."correlation_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_security_event_fk" FOREIGN KEY ("source_security_event_id") REFERENCES "public"."security_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_decision_fk" FOREIGN KEY ("source_policy_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_enforcement_fk" FOREIGN KEY ("source_enforcement_event_id") REFERENCES "public"."enforcement_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_simulations" ADD CONSTRAINT "policy_simulations_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_cases" ADD CONSTRAINT "policy_test_cases_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_cases" ADD CONSTRAINT "policy_test_cases_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_cases" ADD CONSTRAINT "policy_test_cases_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_cases" ADD CONSTRAINT "policy_test_cases_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_test_cases" ADD CONSTRAINT "policy_test_cases_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_allowlists" ADD CONSTRAINT "protection_allowlists_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_allowlists" ADD CONSTRAINT "protection_allowlists_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_allowlists" ADD CONSTRAINT "protection_allowlists_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_blocklists" ADD CONSTRAINT "protection_blocklists_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_blocklists" ADD CONSTRAINT "protection_blocklists_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_blocklists" ADD CONSTRAINT "protection_blocklists_decision_fk" FOREIGN KEY ("source_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_blocklists" ADD CONSTRAINT "protection_blocklists_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_rules" ADD CONSTRAINT "protection_rules_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_rules" ADD CONSTRAINT "protection_rules_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "protection_rules" ADD CONSTRAINT "protection_rules_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_policies" ADD CONSTRAINT "rate_limit_policies_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_policies" ADD CONSTRAINT "rate_limit_policies_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_policies" ADD CONSTRAINT "rate_limit_policies_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_state" ADD CONSTRAINT "rate_limit_state_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_state" ADD CONSTRAINT "rate_limit_state_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rate_limit_state" ADD CONSTRAINT "rate_limit_state_policy_fk" FOREIGN KEY ("rate_limit_policy_id") REFERENCES "public"."rate_limit_policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_events" ADD CONSTRAINT "recovery_events_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_events" ADD CONSTRAINT "recovery_events_region_fk" FOREIGN KEY ("region_id") REFERENCES "public"."platform_regions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_events" ADD CONSTRAINT "recovery_events_backup_fk" FOREIGN KEY ("backup_job_id") REFERENCES "public"."backup_jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "recovery_events" ADD CONSTRAINT "recovery_events_restore_fk" FOREIGN KEY ("restore_operation_id") REFERENCES "public"."restore_operations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "regional_services" ADD CONSTRAINT "regional_services_region_fk" FOREIGN KEY ("region_id") REFERENCES "public"."platform_regions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "regional_services" ADD CONSTRAINT "regional_services_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "residency_policies" ADD CONSTRAINT "residency_policies_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "residency_policies" ADD CONSTRAINT "residency_policies_region_fk" FOREIGN KEY ("home_region_id") REFERENCES "public"."platform_regions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "residency_policies" ADD CONSTRAINT "residency_policies_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_run_fk" FOREIGN KEY ("automation_run_id") REFERENCES "public"."automation_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_step_fk" FOREIGN KEY ("playbook_step_id") REFERENCES "public"."playbook_steps"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_incident_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_decision_fk" FOREIGN KEY ("policy_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_enforcement_fk" FOREIGN KEY ("enforcement_event_id") REFERENCES "public"."enforcement_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_requested_by_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_executed_by_fk" FOREIGN KEY ("executed_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "restore_operations" ADD CONSTRAINT "restore_operations_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "restore_operations" ADD CONSTRAINT "restore_operations_backup_fk" FOREIGN KEY ("backup_job_id") REFERENCES "public"."backup_jobs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "restore_operations" ADD CONSTRAINT "restore_operations_region_fk" FOREIGN KEY ("target_region_id") REFERENCES "public"."platform_regions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "restore_operations" ADD CONSTRAINT "restore_operations_requested_by_fk" FOREIGN KEY ("requested_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "restore_operations" ADD CONSTRAINT "restore_operations_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_playbooks" ADD CONSTRAINT "security_playbooks_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_playbooks" ADD CONSTRAINT "security_playbooks_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_playbooks" ADD CONSTRAINT "security_playbooks_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_playbooks" ADD CONSTRAINT "security_playbooks_approved_by_fk" FOREIGN KEY ("approved_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_simulation_fk" FOREIGN KEY ("simulation_id") REFERENCES "public"."policy_simulations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_policy_version_fk" FOREIGN KEY ("policy_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_decision_fk" FOREIGN KEY ("policy_decision_id") REFERENCES "public"."policy_decisions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "simulation_results" ADD CONSTRAINT "simulation_results_enforcement_fk" FOREIGN KEY ("enforcement_event_id") REFERENCES "public"."enforcement_events"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_region_assignments" ADD CONSTRAINT "tenant_region_assignments_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_region_assignments" ADD CONSTRAINT "tenant_region_assignments_region_fk" FOREIGN KEY ("region_id") REFERENCES "public"."platform_regions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_region_assignments" ADD CONSTRAINT "tenant_region_assignments_assigned_by_fk" FOREIGN KEY ("assigned_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_settings" ADD CONSTRAINT "tenant_settings_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "usage_records" ADD CONSTRAINT "usage_records_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_app_fk" FOREIGN KEY ("developer_app_id") REFERENCES "public"."developer_apps"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_subscriptions" ADD CONSTRAINT "webhook_subscriptions_integration_fk" FOREIGN KEY ("integration_id") REFERENCES "public"."integration_catalog"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policies" ADD CONSTRAINT "zero_trust_policies_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policies" ADD CONSTRAINT "zero_trust_policies_firewall_fk" FOREIGN KEY ("firewall_instance_id") REFERENCES "public"."firewall_instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policies" ADD CONSTRAINT "zero_trust_policies_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policy_versions" ADD CONSTRAINT "ztpv_org_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policy_versions" ADD CONSTRAINT "ztpv_policy_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."zero_trust_policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policy_versions" ADD CONSTRAINT "ztpv_previous_version_fk" FOREIGN KEY ("previous_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policy_versions" ADD CONSTRAINT "ztpv_rollback_from_fk" FOREIGN KEY ("rollback_from_version_id") REFERENCES "public"."zero_trust_policy_versions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "zero_trust_policy_versions" ADD CONSTRAINT "ztpv_created_by_fk" FOREIGN KEY ("created_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ai_reports_org_type_time_idx" ON "ai_analysis_reports" USING btree ("organization_id","report_type","generated_at");--> statement-breakpoint
CREATE INDEX "ai_reports_incident_idx" ON "ai_analysis_reports" USING btree ("incident_id","generated_at");--> statement-breakpoint
CREATE INDEX "ai_reports_session_idx" ON "ai_analysis_reports" USING btree ("session_id","generated_at");--> statement-breakpoint
CREATE INDEX "ai_feedback_org_rating_idx" ON "ai_feedback" USING btree ("organization_id","rating","created_at");--> statement-breakpoint
CREATE INDEX "ai_feedback_message_idx" ON "ai_feedback" USING btree ("message_id");--> statement-breakpoint
CREATE INDEX "ai_feedback_report_idx" ON "ai_feedback" USING btree ("report_id");--> statement-breakpoint
CREATE INDEX "ai_messages_org_time_idx" ON "ai_messages" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "ai_messages_session_time_idx" ON "ai_messages" USING btree ("session_id","created_at");--> statement-breakpoint
CREATE INDEX "ai_sessions_org_status_idx" ON "ai_sessions" USING btree ("organization_id","status","updated_at");--> statement-breakpoint
CREATE INDEX "ai_sessions_user_time_idx" ON "ai_sessions" USING btree ("user_id","updated_at");--> statement-breakpoint
CREATE INDEX "ai_sessions_firewall_idx" ON "ai_sessions" USING btree ("firewall_instance_id","updated_at");--> statement-breakpoint
CREATE UNIQUE INDEX "automation_runs_idempotency_idx" ON "automation_runs" USING btree ("organization_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "automation_runs_org_status_idx" ON "automation_runs" USING btree ("organization_id","status","started_at");--> statement-breakpoint
CREATE INDEX "automation_runs_playbook_idx" ON "automation_runs" USING btree ("playbook_id","started_at");--> statement-breakpoint
CREATE INDEX "automation_runs_firewall_idx" ON "automation_runs" USING btree ("firewall_instance_id","started_at");--> statement-breakpoint
CREATE INDEX "backup_jobs_org_status_idx" ON "backup_jobs" USING btree ("organization_id","status","created_at");--> statement-breakpoint
CREATE INDEX "backup_jobs_region_status_idx" ON "backup_jobs" USING btree ("region_id","status");--> statement-breakpoint
CREATE INDEX "compliance_reports_org_type_time_idx" ON "compliance_reports" USING btree ("organization_id","report_type","period_end");--> statement-breakpoint
CREATE INDEX "compliance_reports_status_idx" ON "compliance_reports" USING btree ("organization_id","status","updated_at");--> statement-breakpoint
CREATE UNIQUE INDEX "credential_protection_state_unique_idx" ON "credential_protection_state" USING btree ("organization_id","credential_fingerprint");--> statement-breakpoint
CREATE INDEX "credential_protection_state_org_status_idx" ON "credential_protection_state" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "credential_protection_state_firewall_idx" ON "credential_protection_state" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE INDEX "customer_contacts_org_type_idx" ON "customer_contacts" USING btree ("organization_id","contact_type");--> statement-breakpoint
CREATE INDEX "customer_contacts_parent_idx" ON "customer_contacts" USING btree ("parent_organization_id");--> statement-breakpoint
CREATE INDEX "delegated_access_provider_status_idx" ON "delegated_access_grants" USING btree ("provider_organization_id","status");--> statement-breakpoint
CREATE INDEX "delegated_access_customer_status_idx" ON "delegated_access_grants" USING btree ("customer_organization_id","status");--> statement-breakpoint
CREATE INDEX "delegated_access_user_status_idx" ON "delegated_access_grants" USING btree ("user_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "developer_apps_org_slug_idx" ON "developer_apps" USING btree ("organization_id","slug");--> statement-breakpoint
CREATE INDEX "developer_apps_org_status_idx" ON "developer_apps" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "emergency_bypasses_org_status_expires_idx" ON "emergency_bypasses" USING btree ("organization_id","status","expires_at");--> statement-breakpoint
CREATE INDEX "emergency_bypasses_firewall_status_idx" ON "emergency_bypasses" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE INDEX "enforcement_events_org_time_idx" ON "enforcement_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "enforcement_events_firewall_time_idx" ON "enforcement_events" USING btree ("firewall_instance_id","created_at");--> statement-breakpoint
CREATE INDEX "enforcement_events_decision_idx" ON "enforcement_events" USING btree ("policy_decision_id");--> statement-breakpoint
CREATE INDEX "enforcement_events_action_idx" ON "enforcement_events" USING btree ("organization_id","action");--> statement-breakpoint
CREATE INDEX "evidence_items_org_time_idx" ON "evidence_items" USING btree ("organization_id","occurred_at");--> statement-breakpoint
CREATE INDEX "evidence_items_case_idx" ON "evidence_items" USING btree ("investigation_case_id","occurred_at");--> statement-breakpoint
CREATE INDEX "evidence_items_run_idx" ON "evidence_items" USING btree ("automation_run_id","occurred_at");--> statement-breakpoint
CREATE INDEX "evidence_items_source_idx" ON "evidence_items" USING btree ("source_type","source_ref_id");--> statement-breakpoint
CREATE UNIQUE INDEX "integration_catalog_slug_idx" ON "integration_catalog" USING btree ("slug");--> statement-breakpoint
CREATE INDEX "integration_catalog_category_status_idx" ON "integration_catalog" USING btree ("category","status");--> statement-breakpoint
CREATE INDEX "integration_catalog_org_idx" ON "integration_catalog" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "investigation_cases_org_status_idx" ON "investigation_cases" USING btree ("organization_id","status","last_seen_at");--> statement-breakpoint
CREATE INDEX "investigation_cases_firewall_idx" ON "investigation_cases" USING btree ("firewall_instance_id","last_seen_at");--> statement-breakpoint
CREATE INDEX "investigation_cases_incident_idx" ON "investigation_cases" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "marketplace_listings_category_status_idx" ON "marketplace_listings" USING btree ("category","status");--> statement-breakpoint
CREATE INDEX "marketplace_listings_publisher_idx" ON "marketplace_listings" USING btree ("publisher_organization_id");--> statement-breakpoint
CREATE UNIQUE INDEX "organization_hierarchy_parent_child_idx" ON "organization_hierarchy" USING btree ("parent_organization_id","child_organization_id");--> statement-breakpoint
CREATE INDEX "organization_hierarchy_parent_status_idx" ON "organization_hierarchy" USING btree ("parent_organization_id","status");--> statement-breakpoint
CREATE INDEX "organization_hierarchy_child_status_idx" ON "organization_hierarchy" USING btree ("child_organization_id","status");--> statement-breakpoint
CREATE INDEX "platform_health_org_time_idx" ON "platform_health_records" USING btree ("organization_id","checked_at");--> statement-breakpoint
CREATE INDEX "platform_health_region_time_idx" ON "platform_health_records" USING btree ("region_id","checked_at");--> statement-breakpoint
CREATE INDEX "platform_health_service_status_idx" ON "platform_health_records" USING btree ("service_type","status","checked_at");--> statement-breakpoint
CREATE UNIQUE INDEX "platform_regions_key_idx" ON "platform_regions" USING btree ("region_key");--> statement-breakpoint
CREATE INDEX "platform_regions_status_idx" ON "platform_regions" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "playbook_steps_order_idx" ON "playbook_steps" USING btree ("playbook_id","step_order");--> statement-breakpoint
CREATE INDEX "playbook_steps_org_idx" ON "playbook_steps" USING btree ("organization_id","playbook_id");--> statement-breakpoint
CREATE INDEX "policy_change_requests_org_status_idx" ON "policy_change_requests" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "policy_change_requests_policy_idx" ON "policy_change_requests" USING btree ("policy_id","policy_version_id");--> statement-breakpoint
CREATE INDEX "policy_change_requests_reviewer_idx" ON "policy_change_requests" USING btree ("reviewer_user_id","status");--> statement-breakpoint
CREATE INDEX "policy_decisions_org_time_idx" ON "policy_decisions" USING btree ("organization_id","evaluated_at");--> statement-breakpoint
CREATE INDEX "policy_decisions_firewall_time_idx" ON "policy_decisions" USING btree ("firewall_instance_id","evaluated_at");--> statement-breakpoint
CREATE INDEX "policy_decisions_policy_time_idx" ON "policy_decisions" USING btree ("policy_id","evaluated_at");--> statement-breakpoint
CREATE INDEX "policy_decisions_event_idx" ON "policy_decisions" USING btree ("security_event_id");--> statement-breakpoint
CREATE INDEX "policy_simulations_org_time_idx" ON "policy_simulations" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "policy_simulations_firewall_time_idx" ON "policy_simulations" USING btree ("firewall_instance_id","created_at");--> statement-breakpoint
CREATE INDEX "policy_simulations_policy_time_idx" ON "policy_simulations" USING btree ("policy_id","created_at");--> statement-breakpoint
CREATE INDEX "policy_simulations_status_idx" ON "policy_simulations" USING btree ("organization_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "policy_test_cases_org_name_idx" ON "policy_test_cases" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "policy_test_cases_org_status_idx" ON "policy_test_cases" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "policy_test_cases_policy_idx" ON "policy_test_cases" USING btree ("policy_id","policy_version_id");--> statement-breakpoint
CREATE UNIQUE INDEX "protection_allowlists_unique_idx" ON "protection_allowlists" USING btree ("organization_id","firewall_instance_id","entry_type","entry_hash");--> statement-breakpoint
CREATE INDEX "protection_allowlists_org_status_idx" ON "protection_allowlists" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "protection_allowlists_expires_idx" ON "protection_allowlists" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "protection_blocklists_unique_idx" ON "protection_blocklists" USING btree ("organization_id","firewall_instance_id","entry_type","entry_hash");--> statement-breakpoint
CREATE INDEX "protection_blocklists_org_status_idx" ON "protection_blocklists" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "protection_blocklists_expires_idx" ON "protection_blocklists" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "protection_rules_org_name_idx" ON "protection_rules" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "protection_rules_org_status_idx" ON "protection_rules" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "protection_rules_firewall_idx" ON "protection_rules" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE INDEX "protection_rules_action_idx" ON "protection_rules" USING btree ("organization_id","action");--> statement-breakpoint
CREATE UNIQUE INDEX "rate_limit_policies_org_name_idx" ON "rate_limit_policies" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "rate_limit_policies_org_status_idx" ON "rate_limit_policies" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "rate_limit_policies_firewall_idx" ON "rate_limit_policies" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "rate_limit_state_unique_idx" ON "rate_limit_state" USING btree ("rate_limit_policy_id","dimension","key_hash","window_start");--> statement-breakpoint
CREATE INDEX "rate_limit_state_org_expires_idx" ON "rate_limit_state" USING btree ("organization_id","expires_at");--> statement-breakpoint
CREATE INDEX "rate_limit_state_firewall_idx" ON "rate_limit_state" USING btree ("firewall_instance_id","window_end");--> statement-breakpoint
CREATE INDEX "recovery_events_org_time_idx" ON "recovery_events" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "recovery_events_region_type_idx" ON "recovery_events" USING btree ("region_id","event_type");--> statement-breakpoint
CREATE INDEX "regional_services_region_type_idx" ON "regional_services" USING btree ("region_id","service_type");--> statement-breakpoint
CREATE INDEX "regional_services_org_type_idx" ON "regional_services" USING btree ("organization_id","service_type");--> statement-breakpoint
CREATE INDEX "regional_services_status_idx" ON "regional_services" USING btree ("status");--> statement-breakpoint
CREATE INDEX "residency_policies_org_status_idx" ON "residency_policies" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "residency_policies_home_region_idx" ON "residency_policies" USING btree ("home_region_id");--> statement-breakpoint
CREATE UNIQUE INDEX "response_actions_idempotency_idx" ON "response_actions" USING btree ("organization_id","idempotency_key");--> statement-breakpoint
CREATE INDEX "response_actions_org_status_idx" ON "response_actions" USING btree ("organization_id","status","created_at");--> statement-breakpoint
CREATE INDEX "response_actions_run_idx" ON "response_actions" USING btree ("automation_run_id","created_at");--> statement-breakpoint
CREATE INDEX "response_actions_incident_idx" ON "response_actions" USING btree ("incident_id","created_at");--> statement-breakpoint
CREATE INDEX "restore_operations_org_status_idx" ON "restore_operations" USING btree ("organization_id","status","created_at");--> statement-breakpoint
CREATE INDEX "restore_operations_backup_idx" ON "restore_operations" USING btree ("backup_job_id");--> statement-breakpoint
CREATE UNIQUE INDEX "security_playbooks_org_name_idx" ON "security_playbooks" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "security_playbooks_org_status_idx" ON "security_playbooks" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "security_playbooks_trigger_idx" ON "security_playbooks" USING btree ("organization_id","trigger_type","status");--> statement-breakpoint
CREATE INDEX "security_playbooks_firewall_idx" ON "security_playbooks" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE INDEX "simulation_results_org_time_idx" ON "simulation_results" USING btree ("organization_id","created_at");--> statement-breakpoint
CREATE INDEX "simulation_results_simulation_idx" ON "simulation_results" USING btree ("simulation_id");--> statement-breakpoint
CREATE INDEX "simulation_results_policy_idx" ON "simulation_results" USING btree ("policy_id","policy_version_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_region_assignments_org_region_type_idx" ON "tenant_region_assignments" USING btree ("organization_id","region_id","assignment_type");--> statement-breakpoint
CREATE INDEX "tenant_region_assignments_org_status_idx" ON "tenant_region_assignments" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "tenant_region_assignments_region_status_idx" ON "tenant_region_assignments" USING btree ("region_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_settings_organization_idx" ON "tenant_settings" USING btree ("organization_id");--> statement-breakpoint
CREATE INDEX "tenant_settings_plan_status_idx" ON "tenant_settings" USING btree ("plan_key","lifecycle_status");--> statement-breakpoint
CREATE INDEX "usage_records_org_metric_period_idx" ON "usage_records" USING btree ("organization_id","metric_type","period_start");--> statement-breakpoint
CREATE INDEX "usage_records_period_idx" ON "usage_records" USING btree ("period_start","period_end");--> statement-breakpoint
CREATE INDEX "webhook_subscriptions_org_status_idx" ON "webhook_subscriptions" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "webhook_subscriptions_app_idx" ON "webhook_subscriptions" USING btree ("developer_app_id");--> statement-breakpoint
CREATE UNIQUE INDEX "zero_trust_policies_org_name_idx" ON "zero_trust_policies" USING btree ("organization_id","name");--> statement-breakpoint
CREATE INDEX "zero_trust_policies_org_status_idx" ON "zero_trust_policies" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "zero_trust_policies_firewall_status_idx" ON "zero_trust_policies" USING btree ("firewall_instance_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "zero_trust_policy_versions_policy_number_idx" ON "zero_trust_policy_versions" USING btree ("policy_id","version_number");--> statement-breakpoint
CREATE INDEX "zero_trust_policy_versions_org_status_idx" ON "zero_trust_policy_versions" USING btree ("organization_id","status");--> statement-breakpoint
CREATE INDEX "zero_trust_policy_versions_policy_status_idx" ON "zero_trust_policy_versions" USING btree ("policy_id","status");