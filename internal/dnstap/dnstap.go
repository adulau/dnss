// Package dnstap exports DNS traffic in the dnstap format.
package dnstap

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/log"
	"github.com/miekg/dns"
)

const contentType = "protobuf:dnstap.Dnstap"

// Writer asynchronously writes dnstap frames to a destination.
type Writer struct {
	network string
	addr    string
	ch      chan record

	once sync.Once
}

type record struct {
	query     *dns.Msg
	response  *dns.Msg
	local     net.Addr
	remote    net.Addr
	transport string
	qt        time.Time
	rt        time.Time
}

// New creates a Writer for destination. The destination can be tcp://host:port,
// unix:///path/to/socket, unix:/path/to/socket, or a bare path (Unix socket).
func New(destination string) *Writer {
	network, addr := parseDestination(destination)
	return &Writer{network: network, addr: addr, ch: make(chan record, 1024)}
}

func parseDestination(destination string) (network, addr string) {
	switch {
	case strings.HasPrefix(destination, "tcp://"):
		return "tcp", strings.TrimPrefix(destination, "tcp://")
	case strings.HasPrefix(destination, "unix://"):
		return "unix", strings.TrimPrefix(destination, "unix://")
	case strings.HasPrefix(destination, "unix:"):
		return "unix", strings.TrimPrefix(destination, "unix:")
	default:
		return "unix", destination
	}
}

// Start starts the background export loop.
func (w *Writer) Start() {
	w.once.Do(func() { go w.run() })
}

// Capture records a DNS query/response pair. It never blocks the DNS server; if
// the export queue is full, the record is dropped.
func (w *Writer) Capture(query, response *dns.Msg, local, remote net.Addr, transport string, queryTime, responseTime time.Time) {
	if w == nil {
		return
	}

	select {
	case w.ch <- record{query: query.Copy(), response: response.Copy(), local: local, remote: remote, transport: transport, qt: queryTime, rt: responseTime}:
	default:
		log.Infof("dnstap export queue full, dropping record")
	}
}

func (w *Writer) run() {
	for {
		conn, err := net.Dial(w.network, w.addr)
		if err != nil {
			log.Infof("dnstap connect to %s:%s failed: %v", w.network, w.addr, err)
			time.Sleep(time.Second)
			continue
		}

		log.Infof("dnstap exporting to %s:%s", w.network, w.addr)
		if err := writeControl(conn, 6, contentType); err != nil { // READY
			log.Infof("dnstap READY failed: %v", err)
			conn.Close()
			continue
		}
		if err := writeControl(conn, 4, contentType); err != nil { // START
			log.Infof("dnstap START failed: %v", err)
			conn.Close()
			continue
		}

		for r := range w.ch {
			frame, err := r.frame()
			if err != nil {
				log.Infof("dnstap encode failed: %v", err)
				continue
			}
			if err := writeData(conn, frame); err != nil {
				log.Infof("dnstap write failed: %v", err)
				conn.Close()
				break
			}
		}
	}
}

func (r record) frame() ([]byte, error) {
	qwire, err := r.query.Pack()
	if err != nil {
		return nil, err
	}
	rwire, err := r.response.Pack()
	if err != nil {
		return nil, err
	}

	msg := []byte{}
	msg = appendVarint(msg, 1, 6) // CLIENT_RESPONSE
	msg = appendVarint(msg, 2, socketFamily(r.remote))
	msg = appendVarint(msg, 3, socketProtocol(r.transport))
	msg = appendBytes(msg, 4, addrBytes(r.remote))
	msg = appendBytes(msg, 5, addrBytes(r.local))
	msg = appendVarint(msg, 6, port(r.remote))
	msg = appendVarint(msg, 7, port(r.local))
	msg = appendVarint(msg, 8, uint64(r.qt.Unix()))
	msg = appendVarint(msg, 9, uint64(r.qt.Nanosecond()))
	msg = appendBytes(msg, 10, qwire)
	msg = appendVarint(msg, 11, uint64(r.rt.Unix()))
	msg = appendVarint(msg, 12, uint64(r.rt.Nanosecond()))
	msg = appendBytes(msg, 13, rwire)

	dt := []byte{}
	dt = appendVarint(dt, 1, 1) // MESSAGE
	dt = appendBytes(dt, 14, msg)
	return dt, nil
}

func writeControl(conn net.Conn, typ uint64, ct string) error {
	payload := []byte{}
	payload = appendVarint(payload, 1, typ)
	if ct != "" {
		payload = appendBytes(payload, 2, []byte(ct))
	}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 0)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	_, err := conn.Write(append(hdr[:], payload...))
	return err
}

func writeData(conn net.Conn, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	_, err := conn.Write(append(hdr[:], payload...))
	return err
}

func appendVarint(b []byte, field int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(field<<3))
	return binary.AppendUvarint(b, v)
}

func appendBytes(b []byte, field int, v []byte) []byte {
	if len(v) == 0 {
		return b
	}
	b = binary.AppendUvarint(b, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func socketProtocol(transport string) uint64 {
	if strings.HasPrefix(transport, "tcp") {
		return 2 // TCP
	}
	return 1 // UDP
}

func socketFamily(addr net.Addr) uint64 {
	ip := ipFromAddr(addr)
	if ip != nil && ip.To4() == nil {
		return 2 // INET6
	}
	return 1 // INET
}

func addrBytes(addr net.Addr) []byte {
	ip := ipFromAddr(addr)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func ipFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}

func port(addr net.Addr) uint64 {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return uint64(a.Port)
	case *net.TCPAddr:
		return uint64(a.Port)
	default:
		_, p, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0
		}
		var n uint64
		for _, c := range p {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + uint64(c-'0')
		}
		return n
	}
}
