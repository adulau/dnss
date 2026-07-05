// Package stats keeps process-wide counters used for dnss monitoring.
package stats

import (
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var counters = expvar.NewMap("dnss")

var domainStats = struct {
	sync.Mutex
	counts map[string]int64
}{counts: map[string]int64{}}

// Add increases the named counter by delta.
func Add(name string, delta int64) {
	counters.Add(name, delta)
}

// Inc increases the named counter by one.
func Inc(name string) {
	Add(name, 1)
}

// RecordDomainQuery records a query for the given domain/hostname.
func RecordDomainQuery(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		name = "."
	}

	domainStats.Lock()
	domainStats.counts[name]++
	domainStats.Unlock()
}

// Report writes a single-line JSON snapshot of all public variables.
func Report(w io.Writer, now time.Time) {
	vars := map[string]json.RawMessage{}
	expvar.Do(func(kv expvar.KeyValue) {
		vars[kv.Key] = json.RawMessage(kv.Value.String())
	})

	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Fprintf(w, "dnss statistics %s", now.Format(time.RFC3339))
	for _, k := range keys {
		fmt.Fprintf(w, " %s=%s", k, vars[k])
	}
	fmt.Fprintln(w)
}

type domainCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func topDomains(limit int) []domainCount {
	if limit <= 0 {
		return []domainCount{}
	}

	domainStats.Lock()
	defer domainStats.Unlock()

	all := make([]domainCount, 0, len(domainStats.counts))
	for name, count := range domainStats.counts {
		all = append(all, domainCount{Name: name, Count: count})
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		return all[i].Name < all[j].Name
	})

	if len(all) > limit {
		all = all[:limit]
	}
	return all
}

// ReportTopDomains writes a single-line JSON snapshot of the most queried domains.
func ReportTopDomains(w io.Writer, now time.Time, limit int) {
	top := topDomains(limit)
	encoded, err := json.Marshal(top)
	if err != nil {
		// This should not happen with domainCount, but keep reporting robust.
		encoded = []byte("[]")
	}

	fmt.Fprintf(w, "dnss top_domains %s limit=%d domains=%s\n",
		now.Format(time.RFC3339), limit, encoded)
}

// PeriodicallyReport writes statistics every interval to w until the process exits.
func PeriodicallyReport(w io.Writer, interval time.Duration) {
	if interval <= 0 {
		return
	}

	for range time.Tick(interval) {
		Report(w, time.Now())
	}
}

// PeriodicallyReportToStderr writes statistics to stderr every interval.
func PeriodicallyReportToStderr(interval time.Duration) {
	PeriodicallyReport(os.Stderr, interval)
}

// PeriodicallyReportTopDomains writes top-domain statistics every interval to w.
func PeriodicallyReportTopDomains(w io.Writer, interval time.Duration, limit int) {
	if interval <= 0 || limit <= 0 {
		return
	}

	for range time.Tick(interval) {
		ReportTopDomains(w, time.Now(), limit)
	}
}

// PeriodicallyReportTopDomainsToStderr writes top-domain statistics to stderr.
func PeriodicallyReportTopDomainsToStderr(interval time.Duration, limit int) {
	PeriodicallyReportTopDomains(os.Stderr, interval, limit)
}
