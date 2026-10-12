// Package engine compiles the pinned Coraza and OWASP CRS configuration.
package engine

import (
	"fmt"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

const CRSVersion = crs.Version

type Options struct {
	Mode             string
	ParanoiaLevel    int
	RequestBodyLimit int64
	InspectResponse  bool
	// ExperimentalRXPrefilter is only exercised by benchmarks. Production
	// configuration leaves Coraza's experimental regex optimization disabled.
	ExperimentalRXPrefilter bool
}

func Config(o Options) (coraza.WAFConfig, error) {
	modes := map[string]string{"detect": "DetectionOnly", "block": "On", "off": "Off"}
	mode, ok := modes[o.Mode]
	if !ok {
		return nil, fmt.Errorf("mode must be detect, block, or off")
	}
	if o.ParanoiaLevel < 1 || o.ParanoiaLevel > 4 {
		return nil, fmt.Errorf("paranoia_level must be 1–4")
	}
	if o.RequestBodyLimit < 1 || o.RequestBodyLimit > 128<<20 {
		return nil, fmt.Errorf("request_body_limit must be 1–134217728 bytes")
	}
	response := "Off"
	if o.InspectResponse {
		response = "On"
	}
	prefilter := "Off"
	if o.ExperimentalRXPrefilter {
		prefilter = "On"
	}
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
SecRxPreFilter %s
SecRuleEngine %s
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess %s
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction ProcessPartial
SecAuditEngine Off
SecAction "id:9000000,phase:1,pass,nolog,setvar:tx.crs_xml_attr_inspect=1,setvar:tx.blocking_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
Include @crs-setup-lts.conf.example
Include @owasp_crs_lts/*.conf
`, prefilter, mode, o.RequestBodyLimit, o.RequestBodyLimit, min(o.RequestBodyLimit, 131072), response, o.ParanoiaLevel)
	return coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives), nil
}

func New(o Options) (coraza.WAF, error) {
	cfg, err := Config(o)
	if err != nil {
		return nil, err
	}
	return coraza.NewWAF(cfg)
}

// Compile accepts full compiler-generated SecLang using only embedded includes.
func Compile(directives string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives))
}
