// Package httpserver implements an HTTPS server which handles DNS requests
// over HTTPS.
//
// It implements DNS Queries over HTTPS (DoH), as specified in RFC 8484:
// https://tools.ietf.org/html/rfc8484.
package httpserver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/adulau/dnss/internal/stats"
	"github.com/adulau/dnss/internal/trace"

	"blitiri.com.ar/go/log"
	"github.com/miekg/dns"
)

// Server is an HTTPS server that implements DNS over HTTPS, see the
// package-level documentation for more references.
type Server struct {
	Addr     string
	Upstream string
	CertFile string
	KeyFile  string
	Insecure bool
}

// ListenAndServe starts the HTTPS server.
func (s *Server) ListenAndServe() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.Resolve)
	mux.HandleFunc("/resolve", s.Resolve)
	srv := http.Server{
		Addr:     s.Addr,
		Handler:  mux,
		ErrorLog: stdlog.New(tlsHandshakeErrorCounter{fallback: os.Stderr}, "", stdlog.LstdFlags),
	}

	log.Infof("HTTPS listening on %s", s.Addr)
	var err error
	if s.Insecure {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(s.CertFile, s.KeyFile)
	}
	log.Fatalf("HTTPS exiting: %s", err)
}

// tlsHandshakeErrorCounter records the TLS handshake errors emitted by net/http
// without forwarding them to stderr. Other server errors are preserved.
type tlsHandshakeErrorCounter struct {
	fallback io.Writer
}

func (w tlsHandshakeErrorCounter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "http: TLS handshake error") {
		stats.Inc("httpserver_tls_handshake_errors_total")
		return len(p), nil
	}

	if w.fallback == nil {
		return len(p), nil
	}

	n, err := w.fallback.Write(p)
	if n < len(p) && err == nil {
		n = len(p)
	}
	return n, err
}

// Resolve incoming DoH requests.
func (s *Server) Resolve(w http.ResponseWriter, req *http.Request) {
	stats.Inc("httpserver_requests_total")
	stats.Inc("httpserver_requests_method_" + req.Method)
	tr := trace.New("httpserver", "/resolve")
	defer tr.Finish()
	tr.Printf("from:%v", req.RemoteAddr)
	tr.Printf("method:%v", req.Method)

	req.ParseForm()

	// Identify DoH requests:
	//  - GET requests have a "dns=" query parameter.
	//  - GET requests with "name=" use the JSON DNS API.
	//  - POST requests have a content-type = application/dns-message.
	if req.Method == "GET" && req.FormValue("dns") != "" {
		tr.Printf("DoH:GET")
		stats.Inc("httpserver_doh_get")
		dnsQuery, err := base64.RawURLEncoding.DecodeString(
			req.FormValue("dns"))
		if err != nil {
			tr.Error(err)
			stats.Inc("httpserver_errors_decode_get")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.resolveDoH(tr, w, dnsQuery)
		return
	}

	if req.Method == "GET" && req.FormValue("name") != "" {
		tr.Printf("JSON:GET")
		stats.Inc("httpserver_json_get")
		s.resolveJSON(tr, w, req)
		return
	}

	if req.Method == "POST" {
		ct, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil {
			tr.Error(err)
			stats.Inc("httpserver_errors_content_type")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if ct == "application/dns-message" {
			tr.Printf("DoH:POST")
			stats.Inc("httpserver_doh_post")
			// Limit the size of request to 4k.
			dnsQuery, err := ioutil.ReadAll(io.LimitReader(req.Body, 4092))
			if err != nil {
				tr.Error(err)
				stats.Inc("httpserver_errors_read_body")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			s.resolveDoH(tr, w, dnsQuery)
			return
		}
	}

	// Could not found how to handle this request.
	tr.Errorf("unknown request type")
	stats.Inc("httpserver_errors_unknown_request_type")
	http.Error(w, "unknown request type", http.StatusUnsupportedMediaType)
}

// jsonDNSMessage is the response format used by the JSON DNS API.
type jsonDNSMessage struct {
	Status   int         `json:"Status"`
	TC       bool        `json:"TC"`
	RD       bool        `json:"RD"`
	RA       bool        `json:"RA"`
	AD       bool        `json:"AD"`
	CD       bool        `json:"CD"`
	Question []jsonDNSRR `json:"Question,omitempty"`
	Answer   []jsonDNSRR `json:"Answer,omitempty"`
}

type jsonDNSRR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

// resolveJSON resolves GET requests using the JSON DNS API used by common DoH
// clients on /resolve (name=example.com&type=A). It supports every query type
// known to the dns package, including newer types such as SVCB and HTTPS.
func (s *Server) resolveJSON(tr *trace.Trace, w http.ResponseWriter, req *http.Request) {
	qtype, err := queryType(req.FormValue("type"))
	if err != nil {
		tr.Error(err)
		stats.Inc("httpserver_errors_json_query_type")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r := &dns.Msg{}
	r.SetQuestion(dns.Fqdn(req.FormValue("name")), qtype)
	if req.FormValue("cd") == "1" || strings.EqualFold(req.FormValue("cd"), "true") {
		r.CheckingDisabled = true
	}

	fromUp, err := exchange(tr, r, s.Upstream)
	if err != nil {
		stats.Inc("httpserver_errors_dns_exchange")
		status, msg := dnsExchangeHTTPError(err)
		tr.Errorf("dns exchange error: %v", err)
		http.Error(w, msg, status)
		return
	}
	if fromUp == nil {
		stats.Inc("httpserver_errors_no_upstream_response")
		err = tr.Errorf("no response from upstream")
		http.Error(w, err.Error(), http.StatusRequestTimeout)
		return
	}

	w.Header().Set("Content-type", "application/dns-json")
	if err := json.NewEncoder(w).Encode(newJSONDNSMessage(fromUp)); err != nil {
		stats.Inc("httpserver_errors_write_response")
	}
}

func queryType(qtype string) (uint16, error) {
	if qtype == "" {
		return dns.TypeA, nil
	}
	if n, err := strconv.ParseUint(qtype, 10, 16); err == nil {
		return uint16(n), nil
	}
	if t, ok := dns.StringToType[strings.ToUpper(qtype)]; ok {
		return t, nil
	}
	return 0, fmt.Errorf("unknown DNS query type %q", qtype)
}

func newJSONDNSMessage(m *dns.Msg) jsonDNSMessage {
	j := jsonDNSMessage{Status: m.Rcode, TC: m.Truncated, RD: m.RecursionDesired, RA: m.RecursionAvailable, AD: m.AuthenticatedData, CD: m.CheckingDisabled}
	for _, q := range m.Question {
		j.Question = append(j.Question, jsonDNSRR{Name: q.Name, Type: q.Qtype})
	}
	for _, a := range m.Answer {
		h := a.Header()
		j.Answer = append(j.Answer, jsonDNSRR{Name: h.Name, Type: h.Rrtype, TTL: h.Ttl, Data: rrData(a)})
	}
	return j
}

func rrData(rr dns.RR) string {
	fields := strings.Fields(rr.String())
	if len(fields) <= 4 {
		return ""
	}
	return strings.Join(fields[4:], " ")
}

// Resolve DNS over HTTPS requests, as specified in RFC 8484.
func (s *Server) resolveDoH(tr *trace.Trace, w http.ResponseWriter, dnsQuery []byte) {
	r := &dns.Msg{}
	err := r.Unpack(dnsQuery)
	if err != nil {
		stats.Inc("httpserver_errors_unpack_dns_query")
		tr.Printf("invalid DNS query: %v", err)
		http.Error(w, "invalid DNS query", http.StatusBadRequest)
		return
	}

	tr.Question(r.Question)
	if len(r.Question) == 1 {
		stats.RecordDomainQuery(r.Question[0].Name)
		stats.Inc(fmt.Sprintf("httpserver_queries_qtype_%d", r.Question[0].Qtype))
		stats.Inc(fmt.Sprintf("httpserver_queries_qclass_%d", r.Question[0].Qclass))
	}

	// Do the DNS request, get the reply.
	fromUp, err := exchange(tr, r, s.Upstream)
	if err != nil {
		stats.Inc("httpserver_errors_dns_exchange")
		status, msg := dnsExchangeHTTPError(err)
		tr.Errorf("dns exchange error: %v", err)
		http.Error(w, msg, status)
		return
	}

	if fromUp == nil {
		stats.Inc("httpserver_errors_no_upstream_response")
		err = tr.Errorf("no response from upstream")
		http.Error(w, err.Error(), http.StatusRequestTimeout)
		return
	}

	tr.Answer(fromUp)
	stats.Inc("httpserver_responses_total")
	stats.Inc(fmt.Sprintf("httpserver_responses_rcode_%d", fromUp.Rcode))

	packed, err := fromUp.Pack()
	if err != nil {
		stats.Inc("httpserver_errors_pack_reply")
		tr.Errorf("cannot pack upstream reply: %v", err)
		writeDNSResponse(w, servfail(r))
		return
	}

	writeDNSResponse(w, packed)
}

func writeDNSResponse(w http.ResponseWriter, packed []byte) {
	w.Header().Set("Content-type", "application/dns-message")
	// TODO: set cache-control based on the response.
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(packed); err != nil {
		stats.Inc("httpserver_errors_write_response")
	}
}

func servfail(req *dns.Msg) []byte {
	resp := &dns.Msg{}
	resp.SetRcode(req, dns.RcodeServerFailure)
	packed, err := resp.Pack()
	if err != nil {
		// This should not happen for a response built from a successfully
		// unpacked request. Keep the HTTP response valid if it does.
		return []byte{}
	}
	return packed
}

const upstreamTimeout = 4 * time.Second

func exchange(tr *trace.Trace, r *dns.Msg, addr string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: upstreamTimeout,
	}

	reply, _, err := c.Exchange(r, addr)
	if err != nil {
		tr.Printf("error on UDP exchange: %v", err)
		return nil, err
	}
	if !reply.Truncated {
		tr.Printf("UDP exchange successful")
		return reply, nil
	}

	// Retry over TCP only when the UDP response is truncated. Other UDP
	// failures are returned as-is so the caller can report the actual upstream
	// failure instead of masking it with a second TCP error.
	tr.Printf("UDP exchange returned truncated reply: %v", reply.MsgHdr)
	tr.Printf("retrying on TCP")

	c = &dns.Client{
		Net:     "tcp",
		Timeout: upstreamTimeout,
	}

	reply, _, err = c.Exchange(r, addr)
	return reply, err
}

func dnsExchangeHTTPError(err error) (int, string) {
	if isTimeout(err) {
		stats.Inc("httpserver_errors_dns_exchange_timeout")
		return http.StatusGatewayTimeout, "upstream DNS server timed out"
	}

	return http.StatusBadGateway, "upstream DNS exchange failed"
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}

	var timeoutErr net.Error
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}
