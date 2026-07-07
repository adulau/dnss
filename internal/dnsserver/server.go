// Package dnsserver implements a DNS server, that uses the given resolvers to
// handle requests.
package dnsserver

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/adulau/dnss/internal/dnstap"
	dnssstats "github.com/adulau/dnss/internal/stats"
	"github.com/adulau/dnss/internal/trace"

	"blitiri.com.ar/go/log"
	"blitiri.com.ar/go/systemd"
	"github.com/miekg/dns"
)

// newID is a channel used to generate new request IDs.
// There is a goroutine created at init() time that will get IDs randomly, to
// help prevent guesses.
var newID chan uint16

func init() {
	// Buffer 100 numbers to avoid blocking on crypto rand.
	newID = make(chan uint16, 100)

	go func() {
		var id uint16
		var err error

		for {
			err = binary.Read(rand.Reader, binary.LittleEndian, &id)
			if err != nil {
				panic(fmt.Sprintf("error creating id: %v", err))
			}

			newID <- id
		}

	}()
}

// Server implements a DNS proxy, which will (mostly) use the given resolver
// to resolve queries.
type Server struct {
	Addr            string
	unqUpstream     string
	serverOverrides DomainMap
	resolver        Resolver
	dnstap          *dnstap.Writer
}

// New *Server, which will listen on addr, use resolver as the backend
// resolver, and use unqUpstream to resolve unqualified queries.
func New(addr string, resolver Resolver, unqUpstream string, serverOverrides DomainMap) *Server {
	return &Server{
		Addr:            addr,
		resolver:        resolver,
		unqUpstream:     unqUpstream,
		serverOverrides: serverOverrides,
	}
}

// SetDnstap configures optional dnstap export for DNS query/response pairs.
func (s *Server) SetDnstap(w *dnstap.Writer) {
	s.dnstap = w
}

// Handler for the incoming DNS queries.
func (s *Server) Handler(w dns.ResponseWriter, r *dns.Msg) {
	queryTime := time.Now()
	dnssstats.Inc("dnsserver_queries_total")
	dnssstats.Inc("dnsserver_queries_transport_" + w.RemoteAddr().Network())
	tr := trace.New("dnsserver.Handler",
		w.RemoteAddr().Network()+" "+w.RemoteAddr().String())
	defer tr.Finish()

	tr.Printf("id:%v", r.Id)
	tr.Question(r.Question)

	// We only support single-question queries.
	if len(r.Question) != 1 {
		tr.Printf("len(Q) != 1, failing")
		dnssstats.Inc("dnsserver_queries_invalid_question_count")
		dnssstats.Inc("dnsserver_replies_rcode_2")
		dns.HandleFailed(w, r)
		return
	}

	// If the domain has a server override, forward to it instead.
	dnssstats.RecordDomainQuery(r.Question[0].Name)
	dnssstats.Inc(fmt.Sprintf("dnsserver_queries_qtype_%d", r.Question[0].Qtype))
	dnssstats.Inc(fmt.Sprintf("dnsserver_queries_qclass_%d", r.Question[0].Qclass))

	override, ok := s.serverOverrides.GetMostSpecific(r.Question[0].Name)
	if ok {
		dnssstats.Inc("dnsserver_queries_override")
		tr.Printf("override found: %q", override)
		u, err := dns.Exchange(r, override)
		if err == nil {
			tr.Answer(u)
			s.writeReply(tr, w, r, u, queryTime)
		} else {
			tr.Printf("override server returned error: %v", err)
			dnssstats.Inc("dnsserver_errors_override")
			dnssstats.Inc("dnsserver_replies_rcode_2")
			dns.HandleFailed(w, r)
		}

		return
	}

	// Forward to the unqualified upstream server if:
	//  - We have one configured.
	//  - There's only one question in the request, to keep things simple.
	//  - The question is unqualified (only one '.' in the name).
	useUnqUpstream := s.unqUpstream != "" &&
		dns.CountLabel(r.Question[0].Name) <= 1
	if useUnqUpstream {
		dnssstats.Inc("dnsserver_queries_unqualified_upstream")
		u, err := dns.Exchange(r, s.unqUpstream)
		if err == nil {
			tr.Printf("used unqualified upstream")
			tr.Answer(u)
			s.writeReply(tr, w, r, u, queryTime)
		} else {
			tr.Printf("unqualified upstream error: %v", err)
			dnssstats.Inc("dnsserver_errors_unqualified_upstream")
			dnssstats.Inc("dnsserver_replies_rcode_2")
			dns.HandleFailed(w, r)
		}

		return
	}

	// Create our own IDs, in case different users pick the same id and we
	// pass that upstream.
	oldid := r.Id
	r.Id = <-newID

	dnssstats.Inc("dnsserver_queries_resolver")
	fromUp, err := s.resolver.Query(r, tr)
	if err != nil {
		log.Infof("resolver query error: %v", err)
		tr.Error(err)
		dnssstats.Inc("dnsserver_errors_resolver")

		r.Id = oldid
		dnssstats.Inc("dnsserver_replies_rcode_2")
		dns.HandleFailed(w, r)
		return
	}

	tr.Answer(fromUp)

	fromUp.Id = oldid
	s.writeReply(tr, w, r, fromUp, queryTime)
}

func (s *Server) writeReply(tr *trace.Trace, w dns.ResponseWriter, r, reply *dns.Msg, queryTime time.Time) {
	if s.dnstap != nil {
		s.dnstap.Capture(r, reply, w.LocalAddr(), w.RemoteAddr(), w.RemoteAddr().Network(), queryTime, time.Now())
	}
	dnssstats.Inc(fmt.Sprintf("dnsserver_replies_rcode_%d", reply.Rcode))
	if w.RemoteAddr().Network() == "udp" {
		// We need to check if the response fits.
		// UDP by default has a maximum of 512 bytes. This can be extended via
		// the client in the EDNS0 record.
		max := 512
		ednsOPT := r.IsEdns0()
		if ednsOPT != nil {
			max = int(ednsOPT.UDPSize())
		}
		reply.Truncate(max)
		tr.Printf("UDP max:%d truncated:%v", max, reply.Truncated)
		if reply.Truncated {
			dnssstats.Inc("dnsserver_replies_truncated")
		}
	}

	if err := w.WriteMsg(reply); err != nil {
		dnssstats.Inc("dnsserver_errors_write_reply")
	}
}

// ListenAndServe launches the DNS proxy.
func (s *Server) ListenAndServe() {
	err := s.resolver.Init()
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}

	go s.resolver.Maintain()

	if s.Addr == "systemd" {
		s.systemdServe()
	} else {
		s.classicServe()
	}
}

func (s *Server) classicServe() {
	log.Infof("DNS listening on %s", s.Addr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := dns.ListenAndServe(s.Addr, "udp", dns.HandlerFunc(s.Handler))
		log.Fatalf("Exiting UDP: %v", err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := dns.ListenAndServe(s.Addr, "tcp", dns.HandlerFunc(s.Handler))
		log.Fatalf("Exiting TCP: %v", err)
	}()

	wg.Wait()
}

func (s *Server) systemdServe() {
	fsMap, err := systemd.Files()
	if err != nil {
		log.Fatalf("Error getting systemd listeners: %v", err)
	}

	// We will usually have at least one TCP socket and one UDP socket.
	// PacketConns are UDP sockets, Listeners are TCP sockets.
	pconns := []net.PacketConn{}
	listeners := []net.Listener{}
	for _, fs := range fsMap {
		for _, f := range fs {
			if lis, err := net.FileListener(f); err == nil {
				listeners = append(listeners, lis)
				f.Close()
			} else if pc, err := net.FilePacketConn(f); err == nil {
				pconns = append(pconns, pc)
				f.Close()
			}
		}
	}

	var wg sync.WaitGroup

	for _, pconn := range pconns {
		if pconn == nil {
			continue
		}

		wg.Add(1)
		go func(c net.PacketConn) {
			defer wg.Done()
			log.Infof("Activate on packet connection (UDP): %v", c.LocalAddr())
			err := dns.ActivateAndServe(nil, c, dns.HandlerFunc(s.Handler))
			log.Fatalf("Exiting UDP listener: %v", err)
		}(pconn)
	}

	for _, lis := range listeners {
		if lis == nil {
			continue
		}

		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			log.Infof("Activate on listening socket (TCP): %v", l.Addr())
			err := dns.ActivateAndServe(l, nil, dns.HandlerFunc(s.Handler))
			log.Fatalf("Exiting TCP listener: %v", err)
		}(lis)
	}

	wg.Wait()

	// We should only get here if there were no useful sockets.
	log.Fatalf("No systemd sockets, did you forget the .socket?")
}
