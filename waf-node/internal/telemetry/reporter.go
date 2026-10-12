// Package telemetry batches request observations and spools deliveries before
// publishing. Unacknowledged files survive an agent restart and keep batch IDs.
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MonthyG/WAF/waf-node/internal/proxy"
	"github.com/nats-io/nats.go"
)

type Batch struct {
	ID       string              `json:"batch_id"`
	NodeID   string              `json:"node_id"`
	Requests []proxy.Observation `json:"requests"`
}
type Reporter struct {
	nodeID, dir string
	js          nats.JetStreamContext
	input       chan proxy.Observation
	stop, done  chan struct{}
	Dropped     atomic.Uint64
	Failures    atomic.Uint64
}

func New(nodeID, dir string, nc *nats.Conn) (*Reporter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	js, err := nc.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		return nil, err
	}
	r := &Reporter{nodeID: nodeID, dir: dir, js: js, input: make(chan proxy.Observation, 10000), stop: make(chan struct{}), done: make(chan struct{})}
	go r.run()
	return r, nil
}
func (r *Reporter) Observe(o proxy.Observation) {
	select {
	case r.input <- o:
	default:
		r.Dropped.Add(1)
	}
}
func (r *Reporter) Close() { close(r.stop); <-r.done }
func (r *Reporter) spool(requests []proxy.Observation) {
	if len(requests) == 0 {
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		r.Dropped.Add(uint64(len(requests)))
		return
	}
	batch := Batch{ID: hex.EncodeToString(id[:]), NodeID: r.nodeID, Requests: requests}
	data, err := json.Marshal(batch)
	if err != nil {
		r.Dropped.Add(uint64(len(requests)))
		return
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		r.Dropped.Add(uint64(len(requests)))
		return
	}
	// Cap local spool at 256 MiB; overload is visible in management metrics.
	var size int64
	for _, entry := range entries {
		if info, e := entry.Info(); e == nil {
			size += info.Size()
		}
	}
	if size+int64(len(data)) > 256<<20 {
		r.Dropped.Add(uint64(len(requests)))
		return
	}
	path := filepath.Join(r.dir, batch.ID+".json")
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		_, err = file.Write(data)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		r.Dropped.Add(uint64(len(requests)))
		slog.Error("telemetry spool write failed")
		return
	}
}
func (r *Reporter) publish() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		r.Failures.Add(1)
		return
	}
	// Bound each retry sweep to avoid starving new observations during recovery.
	delivered := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(r.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			r.Failures.Add(1)
			return
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if _, err = r.js.Publish("waf.events."+r.nodeID, data, nats.MsgId(r.nodeID+"-"+id)); err != nil {
			r.Failures.Add(1)
			return
		}
		if err = os.Remove(path); err != nil {
			r.Failures.Add(1)
			return
		}
		delivered++
		if delivered >= 32 {
			return
		}
	}
}
func (r *Reporter) run() {
	defer close(r.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	batch := make([]proxy.Observation, 0, 128)
	flush := func() { r.spool(batch); batch = make([]proxy.Observation, 0, 128) }
	r.publish()
	for {
		select {
		case value := <-r.input:
			batch = append(batch, value)
			if len(batch) >= 128 {
				flush()
				r.publish()
			}
		case <-ticker.C:
			flush()
			r.publish()
		case <-r.stop:
			for {
				select {
				case value := <-r.input:
					batch = append(batch, value)
					if len(batch) >= 128 {
						flush()
					}
				default:
					flush()
					r.publish()
					return
				}
			}
		}
	}
}
func (r *Reporter) Metrics() string {
	return fmt.Sprintf("# TYPE waf_telemetry_dropped_total counter\nwaf_telemetry_dropped_total %d\n# TYPE waf_telemetry_publish_failures_total counter\nwaf_telemetry_publish_failures_total %d\n", r.Dropped.Load(), r.Failures.Load())
}
