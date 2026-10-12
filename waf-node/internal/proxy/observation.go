package proxy

import (
	"net/http"
	"time"
)

// Observation excludes query strings, headers, cookies, request/response bodies,
// and rule-matched data. Path is bounded and only included for security events.
type Observation struct {
	EventID    string    `json:"event_id"`
	SiteID     string    `json:"site_id"`
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Method     string    `json:"method"`
	Path       string    `json:"path,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	RuleIDs    []int     `json:"rule_ids,omitempty"`
	Status     int       `json:"status"`
	BytesOut   int64     `json:"bytes_out"`
	DurationMS float64   `json:"duration_ms"`
}

type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseCapture) WriteHeader(status int) {
	if status >= 200 && w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}
func (w *responseCapture) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}
