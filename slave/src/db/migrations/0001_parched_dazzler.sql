CREATE TABLE "waf_bundles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"site_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"payload" jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "waf_bundles" ADD CONSTRAINT "waf_bundles_site_id_waf_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."waf_sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "waf_bundles_site_unique" ON "waf_bundles" USING btree ("site_id");