package otlplogtest

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func str(v string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}
}

func post(t *testing.T, c *Collector, path string, body []byte) int {
	t.Helper()
	resp, err := http.Post(c.URL+path, "application/x-protobuf", bytes.NewReader(body)) //nolint:noctx // test-local server
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestCollector_KeepsRecordsWithTheirResource(t *testing.T) {
	c := New(t)
	body, err := proto.Marshal(&collogs.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: "service.name", Value: str("svc")}}},
		ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{
			{Body: str("one"), SeverityText: "info", Attributes: []*commonpb.KeyValue{{Key: "k", Value: str("field-value")}}},
			{Body: str("two"), SeverityText: "error"},
		}}},
	}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if code := post(t, c, logsPath, body); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	got := c.Records()
	if len(got) != 2 || got[0].Body != "one" || !strings.Contains(got[0].Attributes["k"], "field-value") || got[1].Severity != "error" || got[1].Resource["service.name"] != "svc" {
		t.Fatalf("records = %+v", got)
	}
}

func TestCollector_RefusesTheWrongPathAndBadBodies(t *testing.T) {
	c := New(t)
	if code := post(t, c, "/v1/traces", nil); code != http.StatusNotFound {
		t.Errorf("wrong path: status = %d, want 404", code)
	}
	if code := post(t, c, logsPath, []byte{0xff, 0xff}); code != http.StatusBadRequest {
		t.Errorf("bad body: status = %d, want 400", code)
	}
	rec := httptest.NewRecorder()
	c.serve(rec, httptest.NewRequest(http.MethodPost, logsPath, failingReader{}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unreadable body: status = %d, want 400", rec.Code)
	}
	if n := len(c.Records()); n != 0 {
		t.Fatalf("kept %d records from refused requests, want 0", n)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
