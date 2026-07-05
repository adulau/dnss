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

func TestReportTopDomains(t *testing.T) {
	RecordDomainQuery("Example.COM.")
	RecordDomainQuery("example.com")
	RecordDomainQuery("b.example.")
	RecordDomainQuery("a.example.")
	RecordDomainQuery("a.example.")

	buf := bytes.Buffer{}
	ReportTopDomains(&buf, time.Date(2026, 7, 5, 12, 1, 0, 0, time.UTC), 2)

	got := buf.String()
	if !strings.Contains(got, "dnss top_domains 2026-07-05T12:01:00Z limit=2") {
		t.Fatalf("report missing timestamp or limit: %q", got)
	}
	if !strings.Contains(got, `domains=[{"name":"a.example","count":2},{"name":"example.com","count":2}]`) {
		t.Fatalf("report missing sorted top domains: %q", got)
	}
}

func TestReportTopDomainsDisabledLimit(t *testing.T) {
	RecordDomainQuery("disabled-limit.example.")

	buf := bytes.Buffer{}
	ReportTopDomains(&buf, time.Date(2026, 7, 5, 12, 2, 0, 0, time.UTC), 0)

	got := buf.String()
	if !strings.Contains(got, `limit=0 domains=[]`) {
		t.Fatalf("report with limit 0 should not include domains: %q", got)
	}
}
