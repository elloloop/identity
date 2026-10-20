// Package otlplogtest provides an in-process OTLP/HTTP log collector for
// tests. Production code MUST NOT import this package.
package otlplogtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// logsPath is where the OTLP/HTTP exporter posts logs under its base URL.
const logsPath = "/v1/logs"

// Record is one received log record with the resource it was sent under.
// Attributes holds the record's own attributes, each value in its OTLP text
// form, so a test can check what a field carried whatever its type.
type Record struct {
	Body       string
	Severity   string
	Attributes map[string]string
	Resource   map[string]string
}

// Collector accepts OTLP/HTTP protobuf log exports and keeps what it
// received.
type Collector struct {
	// URL is the base URL to set as the exporter's endpoint.
	URL string

	mu      sync.Mutex
	records []Record
}

// New starts a collector that is closed when t ends. It answers 404 on any
// path but /v1/logs and 400 to a body that does not decode, keeping nothing,
// so an export sent to the wrong place shows up as missing records.
func New(t *testing.T) *Collector {
	t.Helper()
	c := &Collector{}
	srv := httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(srv.Close)
	c.URL = srv.URL
	return c
}

func (c *Collector) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != logsPath {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req collogs.ExportLogsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.add(&req)
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
}

func (c *Collector) add(req *collogs.ExportLogsServiceRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rl := range req.GetResourceLogs() {
		res := map[string]string{}
		for _, kv := range rl.GetResource().GetAttributes() {
			res[kv.GetKey()] = kv.GetValue().GetStringValue()
		}
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				attrs := map[string]string{}
				for _, kv := range lr.GetAttributes() {
					attrs[kv.GetKey()] = prototext.Format(kv.GetValue())
				}
				c.records = append(c.records, Record{
					Body:       lr.GetBody().GetStringValue(),
					Severity:   lr.GetSeverityText(),
					Attributes: attrs,
					Resource:   res,
				})
			}
		}
	}
}

// Records returns every record received so far.
func (c *Collector) Records() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.records...)
}
