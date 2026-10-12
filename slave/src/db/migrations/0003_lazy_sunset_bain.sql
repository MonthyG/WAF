CREATE TABLE "waf_acme_accounts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"directory" text NOT NULL,
	"email" text NOT NULL,
	"key_encrypted" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "waf_acme_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"site_id" uuid NOT NULL,
	"token" text NOT NULL,
	"authorization" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "waf_acme_challenges" ADD CONSTRAINT "waf_acme_challenges_site_id_waf_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."waf_sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "waf_acme_account_unique" ON "waf_acme_accounts" USING btree ("directory","email");--> statement-breakpoint
CREATE UNIQUE INDEX "waf_acme_challenge_unique" ON "waf_acme_challenges" USING btree ("site_id","token");