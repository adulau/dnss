package stats

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestReportIncludesCounters(t *testing.T) {
	Inc("test_counter")

	buf := bytes.Buffer{}
	Report(&buf, time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC))

	got := buf.String()
	if !strings.Contains(got, "dnss statistics 2026-07-05T12:00:00Z") {
		t.Fatalf("report missing timestamp: %q", got)
	}
	if !strings.Contains(got, `dnss={"test_counter": 1}`) {
		t.Fatalf("report missing counter: %q", got)
	}
}
