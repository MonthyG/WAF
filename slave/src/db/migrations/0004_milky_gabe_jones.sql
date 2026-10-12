CREATE TABLE "waf_site_node_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"project_id" uuid NOT NULL,
	"region_id" text NOT NULL,
	"site_id" uuid NOT NULL,
	"node_id" uuid NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "waf_site_node_history_unique" ON "waf_site_node_history" USING btree ("site_id","node_id");