CREATE TABLE "waf_audit" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"user_id" text NOT NULL,
	"action" text NOT NULL,
	"resource_id" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_certificates" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"source" text NOT NULL,
	"domains" jsonb NOT NULL,
	"cert_pem" text,
	"key_pem_encrypted" text,
	"not_after" timestamp with time zone,
	"acme_status" text,
	"last_error" text
);
--> statement-breakpoint
CREATE TABLE "waf_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"kind" text NOT NULL,
	"site_id" uuid,
	"revision" bigint,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"last_error" text
);
--> statement-breakpoint
CREATE TABLE "waf_nodes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"region_id" text NOT NULL,
	"kind" text NOT NULL,
	"project_id" uuid,
	"nova_instance_id" uuid,
	"mgmt_ip" text NOT NULL,
	"public_ip" text NOT NULL,
	"version" text NOT NULL,
	"status" text DEFAULT 'offline' NOT NULL,
	"last_heartbeat_at" timestamp with time zone,
	"applied_revision_map" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_origins" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"site_id" uuid NOT NULL,
	"address" text NOT NULL,
	"port" integer NOT NULL,
	"scheme" text NOT NULL,
	"weight" integer DEFAULT 1 NOT NULL,
	"health_check_path" text DEFAULT '/' NOT NULL,
	"instance_id" uuid
);
--> statement-breakpoint
CREATE TABLE "waf_policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"name" text NOT NULL,
	"engine_mode" text DEFAULT 'detect' NOT NULL,
	"paranoia_level" integer DEFAULT 1 NOT NULL,
	"inbound_anomaly_threshold" integer DEFAULT 5 NOT NULL,
	"outbound_anomaly_threshold" integer DEFAULT 4 NOT NULL,
	"request_body_limit_kb" integer DEFAULT 1024 NOT NULL,
	"inspect_response_body" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_waf_products" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"region_id" text NOT NULL,
	"name" text NOT NULL,
	"mode" text NOT NULL,
	"monthly_price" numeric(12, 4) NOT NULL,
	"included_requests_m" integer NOT NULL,
	"per_million_price" numeric(12, 4) NOT NULL,
	"included_sites" integer NOT NULL,
	"hidden" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"policy_id" uuid NOT NULL,
	"priority" integer NOT NULL,
	"type" text NOT NULL,
	"spec" jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_site_nodes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"site_id" uuid NOT NULL,
	"node_id" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_sites" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"hostname" text NOT NULL,
	"mode" text DEFAULT 'shared' NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"policy_id" uuid NOT NULL,
	"certificate_id" uuid,
	"http_redirect" boolean DEFAULT false NOT NULL,
	"config_revision" bigint DEFAULT 1 NOT NULL,
	"applied_revision" bigint DEFAULT 0 NOT NULL,
	"verification_token" text NOT NULL,
	"verified_at" timestamp with time zone,
	"last_error" text
);
--> statement-breakpoint
ALTER TABLE "waf_origins" ADD CONSTRAINT "waf_origins_site_id_waf_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."waf_sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "waf_rules" ADD CONSTRAINT "waf_rules_policy_id_waf_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."waf_policies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "waf_site_nodes" ADD CONSTRAINT "waf_site_nodes_site_id_waf_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."waf_sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "waf_site_nodes" ADD CONSTRAINT "waf_site_nodes_node_id_waf_nodes_id_fk" FOREIGN KEY ("node_id") REFERENCES "public"."waf_nodes"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "waf_sites" ADD CONSTRAINT "waf_sites_policy_id_waf_policies_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."waf_policies"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "waf_sites" ADD CONSTRAINT "waf_sites_certificate_id_waf_certificates_id_fk" FOREIGN KEY ("certificate_id") REFERENCES "public"."waf_certificates"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "waf_policies_project_idx" ON "waf_policies" USING btree ("project_id");--> statement-breakpoint
CREATE UNIQUE INDEX "waf_site_nodes_unique" ON "waf_site_nodes" USING btree ("site_id","node_id");--> statement-breakpoint
CREATE UNIQUE INDEX "waf_sites_hostname_region_idx" ON "waf_sites" USING btree ("hostname","region_id");--> statement-breakpoint
CREATE INDEX "waf_sites_project_idx" ON "waf_sites" USING btree ("project_id");