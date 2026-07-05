// Package stats keeps process-wide counters used for dnss monitoring.
package stats

import (
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

var counters = expvar.NewMap("dnss")

// Add increases the named counter by delta.
func Add(name string, delta int64) {
	counters.Add(name, delta)
}

// Inc increases the named counter by one.
func Inc(name string) {
	Add(name, 1)
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
