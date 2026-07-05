package nettrace

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"html/template"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"
)

var top *template.Template

func init() {
	top = template.New("_top").Funcs(template.FuncMap{
		"stripZeros":    stripZeros,
		"roundSeconds":  roundSeconds,
		"roundDuration": roundDuration,
		"colorize":      colorize,
		"depthspan":     depthspan,
		"shorttitle":    shorttitle,
		"traceemoji":    traceemoji,
	})

	for _, tmpl := range templateFiles {
		template.Must(top.New(tmpl.name).Parse(tmpl.contents))
	}
}

// RegisterHandler registers a the trace handler in the given ServeMux, on
// `/debug/traces`.
func RegisterHandler(mux *http.ServeMux) {
	mux.HandleFunc("/debug/traces", RenderTraces)
}

// RenderTraces is an http.Handler that renders the tracing information.
func RenderTraces(w http.ResponseWriter, req *http.Request) {
	data := &struct {
		Buckets   *[]time.Duration
		FamTraces map[string]*familyTraces

		// When displaying traces for a specific family.
		Family    string
		Bucket    int
		BucketStr string
		AllGT     bool
		Traces    []*trace

		// When displaying latencies for a specific family.
		Latencies *histSnapshot

		// When displaying a specific trace.
		Trace     *trace
		AllEvents []traceAndEvent

		// Error to show to the user.
		Error string
	}{}

	// Reference the common buckets, no need to copy them.
	data.Buckets = &buckets

	// Copy the family traces map, so we don't have to keep it locked for too
	// long. We'll still need to lock individual entries.
	data.FamTraces = copyFamilies()

	// Default to showing greater-than.
	data.AllGT = true
	if all := req.FormValue("all"); all != "" {
		data.AllGT, _ = strconv.ParseBool(all)
	}

	// Fill in the family related parameters.
	if fam := req.FormValue("fam"); fam != "" {
		if _, ok := data.FamTraces[fam]; !ok {
			data.Family = ""
			data.Error = "Unknown family"
			w.WriteHeader(http.StatusNotFound)
			goto render
		}
		data.Family = fam

		if bs := req.FormValue("b"); bs != "" {
			i, err := strconv.Atoi(bs)
			if err != nil {
				data.Error = "Invalid bucket (not a number)"
				w.WriteHeader(http.StatusBadRequest)
				goto render
			} else if i < -2 || i >= nBuckets {
				data.Error = "Invalid bucket number"
				w.WriteHeader(http.StatusBadRequest)
				goto render
			}
			data.Bucket = i
			data.Traces = data.FamTraces[data.Family].TracesFor(i, data.AllGT)

			switch i {
			case -2:
				data.BucketStr = "errors"
			case -1:
				data.BucketStr = "active"
			default:
				data.BucketStr = buckets[i].String()
			}
		}
	}

	if lat := req.FormValue("lat"); data.Family != "" && lat != "" {
		data.Latencies = data.FamTraces[data.Family].Latencies()
	}

	if traceID := req.FormValue("trace"); traceID != "" {
		refID := req.FormValue("ref")
		tr := findInFamilies(id(traceID), id(refID))
		if tr == nil {
			data.Error = "Trace not found"
			w.WriteHeader(http.StatusNotFound)
			goto render
		}
		data.Trace = tr
		data.Family = tr.Family
		data.AllEvents = allEvents(tr)
	}

render:

	// Write into a buffer, to avoid accidentally holding a lock on http
	// writes. It shouldn't happen, but just to be extra safe.
	bw := &bytes.Buffer{}
	bw.Grow(16 * 1024)
	err := top.ExecuteTemplate(bw, "index.html.tmpl", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		panic(err)
	}

	w.Write(bw.Bytes())
}

type traceAndEvent struct {
	Trace *trace
	Event event
	Depth uint
}

// allEvents gets all the events for the trace and its children/linked traces;
// and returns them sorted by timestamp.
func allEvents(tr *trace) []traceAndEvent {
	// Map tracking all traces we've seen, to avoid loops.
	seen := map[id]bool{}

	// Recursively gather all events.
	evts := appendAllEvents(tr, []traceAndEvent{}, seen, 0)

	// Sort them by time.
	sort.Slice(evts, func(i, j int) bool {
		return evts[i].Event.When.Before(evts[j].Event.When)
	})

	return evts
}

func appendAllEvents(tr *trace, evts []traceAndEvent, seen map[id]bool, depth uint) []traceAndEvent {
	if seen[tr.ID] {
		return evts
	}
	seen[tr.ID] = true

	subTraces := []*trace{}

	// Append all events of this trace.
	trevts := tr.Events()
	for _, e := range trevts {
		evts = append(evts, traceAndEvent{tr, e, depth})
		if e.Ref != nil {
			subTraces = append(subTraces, e.Ref)
		}
	}

	for _, t := range subTraces {
		evts = appendAllEvents(t, evts, seen, depth+1)
	}

	return evts
}

func stripZeros(d time.Duration) string {
	if d < time.Second {
		_, frac := math.Modf(d.Seconds())
		return fmt.Sprintf(" .%6d", int(frac*1000000))
	}
	return fmt.Sprintf("%.6f", d.Seconds())
}

func roundSeconds(d time.Duration) string {
	return fmt.Sprintf("%.6f", d.Seconds())
}

func roundDuration(d time.Duration) time.Duration {
	return d.Round(time.Millisecond)
}

func colorize(depth uint, id id) template.CSS {
	if depth == 0 {
		return template.CSS("rgba(var(--text-color))")
	}

	if depth > 3 {
		depth = 3
	}

	// Must match the number of nested color variables in the CSS.
	colori := crc32.ChecksumIEEE([]byte(id)) % 6
	return template.CSS(
		fmt.Sprintf("var(--nested-d%02d-c%02d)", depth, colori))
}

func depthspan(depth uint) template.HTML {
	s := `<span class="depth">`
	switch depth {
	case 0:
	case 1:
		s += "· "
	case 2:
		s += "· · "
	case 3:
		s += "· · · "
	case 4:
		s += "· · · · "
	default:
		s += fmt.Sprintf("· (%d) · ", depth)
	}

	s += `</span>`
	return template.HTML(s)
}

// Hand-picked emojis that have enough visual differences in most common
// renderings, and are common enough to be able to easily describe them.
var emojids = []rune(`😀🤣😇🥰🤧😈🤡👻👽🤖👋✊🦴👅` +
	`🐒🐕🦊🐱🐯🐎🐄🐷🐑🐐🐪🦒🐘🐀🦇🐓🦆🦚🦜🐢🐍🦖🐋🐟🦈🐙` +
	`🦋🐜🐝🪲🌻🌲🍉🍌🍍🍎🍑🥕🍄` +
	`🧀🍦🍰🧉🚂🚗🚜🛵🚲🛼🪂🚀🌞🌈🌊⚽`)

func shorttitle(tr *trace) string {
	all := tr.Family + " - " + tr.Title
	if len(all) > 20 {
		all = "..." + all[len(all)-17:]
	}
	return all
}

func traceemoji(id id) string {
	i := crc32.ChecksumIEEE([]byte(id)) % uint32(len(emojids))
	return string(emojids[i])
}

type templateFile struct {
	name     string
	contents string
}

var templateFiles = []templateFile{
	{name: "_latency.html.tmpl", contents: `<table class="latencies"><tr>
<td>Count: {{.Latencies.Count}}</td>
<td>Avg: {{.Latencies.Avg | roundDuration}}</td>
<td>Min: {{.Latencies.Min | roundDuration}}</td>
<td>Max: {{.Latencies.Max | roundDuration}}</td>
</tr></table>
<p>

<table class="latencies">
<tr><th>Bucket</th><th>Count</th><th>%</th><th></th><th>Cumulative</th></tr>
{{range .Latencies.Counts}}
<tr>
  <td>
    <a href="?fam={{$.Family}}&b={{.BucketIdx}}"
       {{if eq .Count 0}}class="muted"{{end}}>
        &ge;{{.Start}}</a>
  </td>
  <td>{{.Count}}</td>
  <td>{{.Percent | printf "%5.2f"}}%</td>
  <td><meter max="100" value="{{.Percent}}">
      {{.Percent | printf "%.2f"}}%</meter>
  <td>{{.CumPct | printf "%5.2f"}}%</td>
</tr>
{{end}}
</table>
`},
	{name: "_recursive.html.tmpl", contents: `{{if .Trace.Parent}}
<a href="?trace={{.Trace.Parent.ID}}&ref={{.Trace.ID}}">
  Parent: {{.Trace.Parent.Family}} - {{.Trace.Parent.Title}}</a>
<p>
{{end}}

<table class="trace">

<thead>
<tr>
  <th>Trace</th>
  <th>Timestamp</th>
  <th>Elapsed (s)</th>
  <th></th>
  <th>Message</th>
</tr>
</thead>

<tbody>
{{$prev := .Trace.Start}}
{{range .AllEvents}}
<tr style="background: {{colorize .Depth .Trace.ID}};">
<td title='{{.Trace.Family}} - {{.Trace.Title}}
@ {{.Trace.Start.Format "2006-01-02 15:04:05.999999" }}'>
  {{shorttitle .Trace}}</td>

<td class="when">{{.Event.When.Format "15:04:05.000000"}}</td>
<td class="duration">{{(.Event.When.Sub $prev) | stripZeros}}</td>
<td class="emoji" title='{{.Trace.Family}} - {{.Trace.Title}}
@ {{.Trace.Start.Format "2006-01-02 15:04:05.999999" }}'>
  <div class="emoji">{{traceemoji .Trace.ID}}</div></td>
<td class="msg">
  {{- depthspan .Depth -}}
  {{- if .Event.Type.IsLog -}}
    {{.Event.Msg}}
  {{- else if .Event.Type.IsChild -}}
    new child: <a href="?trace={{.Event.Ref.ID}}&ref={{.Trace.ID}}">{{.Event.Ref.Family}} - {{.Event.Ref.Title}}</a>
  {{- else if .Event.Type.IsLink -}}
    <a href="?trace={{.Event.Ref.ID}}&ref={{.Trace.ID}}">{{.Event.Msg}}</a>
  {{- else if .Event.Type.IsDrop -}}
    <b><i>[ events dropped ]</i></b>
  {{- else -}}
    <i>[ unknown event type ]</i>
  {{- end -}}
</td>
</tr>
{{$prev = .Event.When}}
{{end}}

</tbody>
</table>
`},
	{name: "_single.html.tmpl", contents: `<tr class="title">
<td class="when">{{.Start.Format "2006-01-02 15:04:05.000000"}}</td>
<td class="duration">{{.Duration | roundSeconds}}</td>
<td><a href="?trace={{.ID}}">{{.Title}}</a>
  {{if .Parent}}(parent: <a href="?trace={{.Parent.ID}}&ref={{.ID}}">
    {{.Parent.Family}} - {{.Parent.Title}}</a>)
  {{end}}
</td>
<tr>

{{$prev := .Start}}
{{range .Events}}
<tr>
<td class="when">{{.When.Format "15:04:05.000000"}}</td>
<td class="duration">{{(.When.Sub $prev) | stripZeros}}</td>
<td class="msg">
  {{- if .Type.IsLog -}}
    {{.Msg}}
  {{- else if .Type.IsChild -}}
    new child <a href="?trace={{.Ref.ID}}&ref={{$.ID}}">{{.Ref.Family}} {{.Ref.Title}}</a>
  {{- else if .Type.IsLink -}}
    <a href="?trace={{.Ref.ID}}&ref={{$.ID}}">{{.Msg}}</a>
  {{- else if .Type.IsDrop -}}
    <i>[ events dropped ]</i>
  {{- else -}}
    <i>[ unknown event type ]</i>
  {{- end -}}
</td>
</tr>
{{$prev = .When}}
{{end}}

<tr>
<td>&nbsp;</td>
</tr>
`},
	{name: "index.html.tmpl", contents: `<!DOCTYPE html>
<html lang="en">
<head>
<style>
{{template "style.css"}}
</style>

<title>
{{if .Trace}}{{.Trace.Family}} - {{.Trace.Title}}
{{else if .BucketStr}}{{.Family}} - {{.BucketStr}}
{{else if .Latencies}}{{.Family}} - latency
{{else}}Traces
{{end}}
</title>

</head>

<body>
<h1>Traces</h1>

<table class="index">
{{range $name, $ftr := .FamTraces}}
<tr>
  <td class="family">
    <a href="?fam={{$name}}&b=0&all=true">
    {{if eq $name $.Family}}<u>{{end}}
    {{$name}}
    {{if eq $name $.Family}}</u>{{end}}
    </a>
  </td>

  <td class="bucket active">
    {{$n := $ftr.LenActive}}
    {{if and (eq $name $.Family) (eq "active" $.BucketStr)}}<u>{{end}}

    <a href="?fam={{$name}}&b=-1&all={{$.AllGT}}"
       {{if eq $n 0}}class="muted"{{end}}>
        {{$n}} active</a>

    {{if and (eq $name $.Family) (eq "active" $.BucketStr)}}</u>{{end}}
  </td>

  {{range $i, $b := $.Buckets}}
  <td class="bucket">
    {{$n := $ftr.LenBucket $i}}
    {{if and (eq $name $.Family) (eq $b.String $.BucketStr)}}<u>{{end}}

    <a href="?fam={{$name}}&b={{$i}}&all={{$.AllGT}}"
       {{if eq $n 0}}class="muted"{{end}}>
        &ge;{{$b}}</a>

    {{if and (eq $name $.Family) (eq $b.String $.BucketStr)}}</u>{{end}}
  </td>
  {{end}}

  <td class="bucket">
    {{$n := $ftr.LenErrors}}
    {{if and (eq $name $.Family) (eq "errors" $.BucketStr)}}<u>{{end}}

    <a href="?fam={{$name}}&b=-2&all={{$.AllGT}}"
       {{if eq $n 0}}class="muted"{{end}}>
        errors</a>

    {{if and (eq $name $.Family) (eq "errors" $.BucketStr)}}</u>{{end}}
  </td>

  <td class="bucket">
    <a href="?fam={{$name}}&lat=true&all={{$.AllGT}}">[latency]</a>
  </td>
</tr>
{{end}}
</table>
<br>
Show: <a href="?fam={{.Family}}&b={{.Bucket}}&all=false">
  {{if not .AllGT}}<u>{{end}}
  Only in bucket</a>
  {{if not .AllGT}}</u>{{end}}
/
<a href="?fam={{.Family}}&b={{.Bucket}}&all=true">
  {{if .AllGT}}<u>{{end}}
  All &ge; bucket</a>
  {{if .AllGT}}</u>{{end}}
<p>

<!--------------------------------------------->
{{if .Error}}
<p class="error">Error: {{.Error}}</p>
{{end}}

<!--------------------------------------------->
{{if .BucketStr}}
<h2>{{.Family}} - {{.BucketStr}}</h2>

<table class="trace">
<thead>
<tr>
  <th>Timestamp</th>
  <th>Elapsed (s)</th>
  <th>Message</th>
</tr>
</thead>
<tbody>
<tr>
<td>&nbsp;</td>
</tr>
{{range .Traces}}
{{template "_single.html.tmpl" .}}<p>
{{end}}
</tbody>
</table>

<p>
{{end}}

<!--------------------------------------------->
{{if .Latencies}}
<h2>{{.Family}} - latency</h2>
{{template "_latency.html.tmpl" .}}<p>
{{end}}

<!--------------------------------------------->
{{if .Trace}}
<h2>{{.Trace.Family}} - <i>{{.Trace.Title}}</i></h2>
{{template "_recursive.html.tmpl" .}}<p>
{{end}}

</body>

</html>
`},
	{name: "style.css", contents: `:root {
    --text-color: black;
    --bg-color: #fffff7;
    --zebra-bg-color: #eeeee7;
    --muted-color: #444;
    --xmuted-color: #a1a1a1;
    --link-color: #39c;
    --link-hover: #069;
    --underline-color: grey;
    --error-color: red;

    /* Colors for the nested zebras. */
    --nested-d01-c00: #ffebee;
    --nested-d01-c01: #ede7f6;
    --nested-d01-c02: #e3f2fd;
    --nested-d01-c03: #e8f5e9;
    --nested-d01-c04: #fff8e1;
    --nested-d01-c05: #efebe9;
    --nested-d02-c00: #f0dcdf;
    --nested-d02-c01: #ded8e7;
    --nested-d02-c02: #d4e3ee;
    --nested-d02-c03: #d9e6da;
    --nested-d02-c04: #f0e9d2;
    --nested-d02-c05: #e0dcda;
    --nested-d03-c00: #e1cdd0;
    --nested-d03-c01: #cfc9d8;
    --nested-d03-c02: #c5d4df;
    --nested-d03-c03: #cad7cb;
    --nested-d03-c04: #e1dac3;
    --nested-d03-c05: #d1cdcb;
}

@media (prefers-color-scheme: dark) {
    :root {
        --text-color: rgba(255, 255, 255, 0.90);
        --bg-color: #121212;
        --zebra-bg-color: #222222;
        --muted-color: #aaaaaa;
        --xmuted-color: #a1a1a1;
        --link-color: #44b4ec;
        --link-hover: #7fc9ee;
        --underline-color: grey;
        --error-color: #dd4747;

        /* Colors for the nested zebras. */
        --nested-d01-c00: #220212;
        --nested-d01-c01: #1c1c22;
        --nested-d01-c02: #001e20;
        --nested-d01-c03: #0f0301;
        --nested-d01-c04: #201d06;
        --nested-d01-c05: #00192b;
        --nested-d02-c00: #311121;
        --nested-d02-c01: #2b2b31;
        --nested-d02-c02: #0f2d2f;
        --nested-d02-c03: #1e1210;
        --nested-d02-c04: #2f2c15;
        --nested-d02-c05: #0f283a;
        --nested-d03-c00: #402030;
        --nested-d03-c01: #3a3a40;
        --nested-d03-c02: #1e3c3e;
        --nested-d03-c03: #2d211f;
        --nested-d03-c04: #3e3b24;
        --nested-d03-c05: #1e3749;
    }
}

body {
    font-family: sans-serif;
    color: var(--text-color);
    background: var(--bg-color);
}

p.error {
    color: var(--error-color);
    font-size: large;
}

a {
    color: var(--link-color);
    text-decoration: none;
}

a:hover {
    color: var(--link-hover);
}

.family a {
    color: var(--text-color);
}

u {
    text-decoration-color: var(--underline-color);
}

table.index {
    border-collapse: collapse;
}

table.index tr:nth-child(odd) {

        background-color: var(--zebra-bg-color);
}

table.index td {
    padding: 0.25em 0.5em;
}

table.index td.bucket {
    min-width: 2em;
    text-align: center;
}

table.index td.active {
    /* Make the "active" column wider so there's less jumping on refresh. */
    min-width: 5em;
    text-align: right;
}

table.index a {
    text-decoration: none;
}

a.muted {
    color: var(--muted-color);
}

table.trace {
    font-family: monospace;
    border-collapse: collapse;
}

table.trace thead {
    border-bottom: 1px solid var(--text-color);
}

table.trace th {
    text-align: left;
    padding: 0.1em 1em;
}

table.trace tr.title {
    font-weight: bold;
}

table.trace td {
    padding: 0.1em 1em;
}

table.trace td.when {
    text-align: right;
}

table.trace td.duration {
    text-align: right;
    white-space: pre;
}

table.trace td.msg {
    white-space: pre-wrap;
}

span.depth {
    color: var(--xmuted-color);
}

div.emoji {
    /* Emojis sometimes are rendered excessively tall. */
    /* This ensures they're sized appropriately. */
    max-height: 1.3em;
    overflow: hidden;
}

table.latencies {
    text-align: right;
}

table.latencies td {
    padding: 0 0.3em;
}

table.latencies th {
    text-align: center;
}

meter {
    width: 15em;
}
`},
}
