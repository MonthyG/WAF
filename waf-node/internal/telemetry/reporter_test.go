package telemetry

import (
	"encoding/json"
	"github.com/MonthyG/WAF/waf-node/internal/proxy"
	"os"
	"path/filepath"
	"testing"
)

func TestSpoolPreservesBatchIdentityAndPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	r := &Reporter{nodeID: "node", dir: dir}
	r.spool([]proxy.Observation{{SiteID: "site", EventID: "event", Action: "allowed"}})
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatal("batch not spooled", err)
	}
	path := filepath.Join(dir, files[0].Name())
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var batch Batch
	if err = json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.ID+".json" != files[0].Name() || batch.NodeID != "node" || len(batch.Requests) != 1 || batch.Requests[0].EventID != "event" {
		t.Fatal("spool did not preserve delivery identity")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("spool must be private")
	}
	if r.Dropped.Load() != 0 {
		t.Fatal("spooling dropped data")
	}
}
func TestObserveNeverBlocksOnFullQueue(t *testing.T) {
	r := &Reporter{input: make(chan proxy.Observation, 1)}
	r.Observe(proxy.Observation{})
	r.Observe(proxy.Observation{})
	if r.Dropped.Load() != 1 {
		t.Fatal("overload was not counted")
	}
}
