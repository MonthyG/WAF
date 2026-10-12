// waf-lint compiles administrator SecLang against the exact pinned engine/CRS.
// Input arrives on stdin, never shell command arguments.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/MonthyG/WAF/waf-node/internal/engine"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
)

func main() {
	full := flag.Bool("full", false, "compile a complete SiteBundle policy")
	flag.Parse()
	data, err := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		fmt.Fprintln(os.Stderr, "input exceeds 1 MiB or is unreadable")
		os.Exit(1)
	}
	cfg, err := engine.Config(engine.Options{Mode: "block", ParanoiaLevel: 1, RequestBodyLimit: 1 << 20})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var waf coraza.WAF
	if *full {
		waf, err = engine.Compile(string(data))
	} else {
		waf, err = coraza.NewWAF(cfg.WithDirectives(string(data)))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid SecLang:", err)
		os.Exit(1)
	}
	if closer, ok := waf.(experimental.WAFCloser); ok {
		defer closer.Close()
	}
	fmt.Println(`{"valid":true}`)
}
