#!/usr/bin/env bash
set -euo pipefail
: "WAF_REGION:?Set WAF_REGION}"
: "WAF_PUBLIC_URL:?Set the externally routed WAF API URL, ending /waf/v1}"
: "WAF_INTERNAL_URL:?Set the controller API URL, ending /v1/waf}"
# Uses existing OpenStack CLI authentication. Never stores or prints credentials.
# Run deliberately in the deployment region; onboarding does not invoke this.
if ! openstack service show waf > /dev/null 2>&1; then
  openstack service create --name waf --description 'WAF as a Service' waf
fi
for interface in public internal admin; do
  target="$WAF_INTERNAL_URL"
  [[ "$interface" != public ]] || target="$WAF_PUBLIC_URL"
  existing="$(openstack endpoint list --service waf --region "$WAF_REGION" --interface "$interface" -f value -c ID)"
  if [[ -z "$existing" ]]; then
    openstack endpoint create --region "$WAF_REGION" waf "$interface" "$target"
  else
    echo "Existing $interface endpoint retained; inspect it before changing regional routing."
  fi
done
