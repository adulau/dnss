// Package httpserver implements an HTTPS server which handles DNS requests
// over HTTPS.
//
// It implements DNS Queries over HTTPS (DoH), as specified in RFC 8484:
// https://tools.ietf.org/html/rfc8484.
package httpserver

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"mime"
	"net/http"
	"os"
	"strings"

	"blitiri.com.ar/go/dnss/internal/stats"
	"blitiri.com.ar/go/dnss/internal/trace"

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

// Resolve DNS over HTTPS requests, as specified in RFC 8484.
func (s *Server) resolveDoH(tr *trace.Trace, w http.ResponseWriter, dnsQuery []byte) {
	r := &dns.Msg{}
	err := r.Unpack(dnsQuery)
	if err != nil {
		stats.Inc("httpserver_errors_unpack_dns_query")
		tr.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tr.Question(r.Question)
	if len(r.Question) == 1 {
		stats.Inc(fmt.Sprintf("httpserver_queries_qtype_%d", r.Question[0].Qtype))
		stats.Inc(fmt.Sprintf("httpserver_queries_qclass_%d", r.Question[0].Qclass))
	}

	// Do the DNS request, get the reply.
	fromUp, err := exchange(tr, r, s.Upstream)
	if err != nil {
		stats.Inc("httpserver_errors_dns_exchange")
		err = tr.Errorf("dns exchange error: %v", err)
		http.Error(w, err.Error(), http.StatusFailedDependency)
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
		err = tr.Errorf("cannot pack reply: %v", err)
		http.Error(w, err.Error(), http.StatusFailedDependency)
		return
	}

	// Write the response back.
	w.Header().Set("Content-type", "application/dns-message")
	// TODO: set cache-control based on the response.
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(packed); err != nil {
		stats.Inc("httpserver_errors_write_response")
	}
}

func exchange(tr *trace.Trace, r *dns.Msg, addr string) (*dns.Msg, error) {
	reply, err := dns.Exchange(r, addr)
	if err == nil && !reply.Truncated {
		tr.Printf("UDP exchange successful")
		return reply, err
	}

	// If we had issues over UDP, or the message was truncated, retry over
	// TCP. We don't try beyond that.
	if err != nil {
		tr.Printf("error on UDP exchange: %v", err)
	} else if reply.Truncated {
		tr.Printf("UDP exchange returned truncated reply: %v", reply.MsgHdr)
	}
	tr.Printf("retrying on TCP")

	c := &dns.Client{
		Net: "tcp",
	}

	reply, _, err = c.Exchange(r, addr)
	return reply, err
}
