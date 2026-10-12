//go:build ftw

// Package ftw runs the upstream CRS conformance corpus using go-ftw's log-based
// assertions and the Coraza reference HTTP connector. Production connector
// behavior (routing, block/detect, forwarding, resource limits) is tested in proxy.
package ftw

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corazaconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crstests "github.com/corazawaf/coraza-coreruleset/lts/tests/v4"
	crs "github.com/corazawaf/coraza-coreruleset/lts/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	albedo "github.com/coreruleset/albedo/server"
	"github.com/coreruleset/go-ftw/v2/config"
	"github.com/coreruleset/go-ftw/v2/output"
	"github.com/coreruleset/go-ftw/v2/runner"
	"github.com/coreruleset/go-ftw/v2/test"
	"github.com/jcchavezs/mergefs"
	"github.com/rs/zerolog"
)

func TestCRS(t *testing.T) {
	errorPath := filepath.Join(t.TempDir(), "error.log")
	f, err := os.Create(errorPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var mu sync.Mutex
	// These are the upstream regression prerequisites, not the production policy.
	// PL4 + DetectionOnly is required so every expected rule can log a match.
	directives := `
Include @coraza.conf-recommended
SecAuditEngine Off
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecAction "id:900005,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly,ctl:ruleRemoveById=910000,setvar:tx.crs_xml_attr_inspect=1,setvar:tx.blocking_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:999999,phase:1,pass,t:none,log,msg:'X-CRS-Test %{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
Include @crs-setup-lts.conf.example
Include @owasp_crs_lts/*.conf
`
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(mergefs.Merge(crs.FS, corazaconf.FS)).WithDirectives(directives).WithErrorCallback(func(rule types.MatchedRule) {
		mu.Lock()
		defer mu.Unlock()
		if _, err := io.WriteString(f, rule.ErrorLog()+"\n"); err != nil {
			t.Error(err)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		defer closer.Close()
	}
	s := httptest.NewServer(corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		albedo.Handler().ServeHTTP(w, r)
	})))
	defer s.Close()
	var tests []*test.FTWTest
	err = fs.WalkDir(crstests.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := fs.ReadFile(crstests.FS, path)
		if err != nil {
			return err
		}
		testFile, err := test.GetTestFromYaml(data, path)
		if err != nil {
			return err
		}
		tests = append(tests, testFile)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tests) == 0 {
		t.Fatal("no regression tests loaded")
	}
	u, _ := url.Parse(s.URL)
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	cfg, err := config.NewConfigFromString("testoverride: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogFile = errorPath
	cfg.TestOverride.Overrides.DestAddr = &host
	cfg.TestOverride.Overrides.Port = &port
	rc := config.NewRunnerConfiguration(cfg)
	rc.ReadTimeout = 3 * time.Second
	platform := os.Getenv("WAF_FTW_PLATFORM") == "1"
	if platform { if err := rc.LoadPlatformOverrides("platform-overrides.yaml"); err != nil { t.Fatal(err) } }
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	filter := os.Getenv("WAF_FTW_INCLUDE")
	if filter != "" {
		rc.Include, err = regexp.Compile(filter)
		if err != nil { t.Fatal(err) }
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	res, err := runner.Run(rc, tests, output.NewOutput("quiet", os.Stdout))
	if err != nil {
		t.Fatal(err)
	}
	stats := res.Stats
	passed := len(stats.Success)
	total := passed + stats.TotalFailed() + len(stats.Skipped) + len(stats.Ignored) + len(stats.ForcedPass)
	if total == 0 {
		t.Fatal("zero executed tests")
	}
	percent := 100 * float64(passed) / float64(total)
	report := map[string]any{"crs": crs.Version, "passed": passed, "failed": stats.Failed, "forced_fail": stats.ForcedFail, "skipped": stats.Skipped, "ignored": stats.Ignored, "forced_pass": stats.ForcedPass, "total": total, "pass_percent": percent, "duration": stats.TotalTime.String(), "recorded_at": time.Now().UTC().Format(time.RFC3339)}
	if err := os.MkdirAll("../reports", 0755); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := "../reports/ftw.json"
	if platform { reportPath = "../reports/ftw-platform.json" }
	if filter != "" { reportPath = "../reports/ftw-filtered.json" }
	if err := os.WriteFile(reportPath, append(data, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("CRS %s: %d/%d passed (%.3f%%); failed=%v skipped=%d ignored=%d forced_pass=%d platform=%t", crs.Version, passed, total, percent, stats.Failed, len(stats.Skipped), len(stats.Ignored), len(stats.ForcedPass), platform)
	// Preserve the runner's failures even if the design's >=99% threshold is met.
	// The report records threshold evidence without turning failures into passes.
	if stats.TotalFailed() > 0 {
		t.Errorf("go-ftw reported %d failures; see %s", stats.TotalFailed(), reportPath)
	}
	if filter == "" && percent < 99 {
		t.Errorf("Phase 1 acceptance requires >=99%%; got %.3f%%", percent)
	}
}
