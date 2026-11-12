package dns

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// startSOATestServer starts a local UDP or TCP DNS server.
func startSOATestServer(
	t *testing.T,
	network string,
	address string,
	handler mdns.HandlerFunc,
) string {
	t.Helper()

	server := &mdns.Server{Handler: handler}
	var localAddress net.Addr

	switch network {
	case "udp":
		conn, err := net.ListenPacket("udp", address)
		if err != nil {
			t.Fatalf("start UDP listener: %v", err)
		}
		server.PacketConn = conn
		localAddress = conn.LocalAddr()

	case "tcp":
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatalf("start TCP listener: %v", err)
		}
		server.Listener = listener
		localAddress = listener.Addr()

	default:
		t.Fatalf("unsupported test network: %s", network)
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	_, port, err := net.SplitHostPort(localAddress.String())
	if err != nil {
		t.Fatalf("get DNS server port: %v", err)
	}

	return port
}

func testSOARecord() *mdns.SOA {
	return &mdns.SOA{
		Hdr: mdns.RR_Header{
			Name:   "example.com.",
			Rrtype: mdns.TypeSOA,
			Class:  mdns.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  2026111201,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
}

func TestLookupSOAFromServersUDP(t *testing.T) {
	handler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		if len(request.Question) != 1 {
			t.Error("expected one DNS question")
			return
		}

		question := request.Question[0]
		if question.Name != "example.com." ||
			question.Qtype != mdns.TypeSOA ||
			question.Qclass != mdns.ClassINET {
			t.Errorf("unexpected DNS question: %+v", question)
		}

		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{testSOARecord()}

		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	}

	port := startSOATestServer(
		t, "udp", "127.0.0.1:0", handler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	record, err := lookupSOAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := &SOARecord{
		NS:      "ns1.example.com.",
		MBox:    "hostmaster.example.com.",
		Serial:  2026111201,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		MinTTL:  3600,
	}

	if !reflect.DeepEqual(record, expected) {
		t.Errorf("expected %+v, got %+v", expected, record)
	}
}

func TestLookupSOAFromServersTCPFallback(t *testing.T) {
	var udpCalled atomic.Bool
	var tcpCalled atomic.Bool

	tcpHandler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		tcpCalled.Store(true)

		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = []mdns.RR{testSOARecord()}

		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write TCP response: %v", err)
		}
	}

	udpHandler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		udpCalled.Store(true)

		response := new(mdns.Msg)
		response.SetReply(request)
		response.Truncated = true

		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write UDP response: %v", err)
		}
	}

	port := startSOATestServer(
		t, "tcp", "127.0.0.1:0", tcpHandler,
	)

	startSOATestServer(
		t,
		"udp",
		net.JoinHostPort("127.0.0.1", port),
		udpHandler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	record, err := lookupSOAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if record == nil {
		t.Fatal("expected SOA record")
	}

	if !udpCalled.Load() {
		t.Error("expected UDP query")
	}

	if !tcpCalled.Load() {
		t.Error("expected TCP fallback")
	}

	if record.NS != "ns1.example.com." {
		t.Errorf("unexpected nameserver: %q", record.NS)
	}
}

func TestLookupSOAFromServersDNSFailure(t *testing.T) {
	tests := []struct {
		name string
		code int
		want string
	}{
		{"NXDOMAIN", mdns.RcodeNameError, "NXDOMAIN"},
		{"SERVFAIL", mdns.RcodeServerFailure, "SERVFAIL"},
		{"REFUSED", mdns.RcodeRefused, "REFUSED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := func(
				w mdns.ResponseWriter,
				request *mdns.Msg,
			) {
				response := new(mdns.Msg)
				response.SetRcode(request, tt.code)
				_ = w.WriteMsg(response)
			}

			port := startSOATestServer(
				t, "udp", "127.0.0.1:0", handler,
			)

			ctx, cancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			defer cancel()

			_, err := lookupSOAFromServers(
				ctx, "example.com",
				[]string{"127.0.0.1"}, port,
			)

			if err == nil {
				t.Fatal("expected DNS error")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected %q in error, got %v",
					tt.want, err)
			}
		})
	}
}

func TestLookupSOAFromServersNoRecord(t *testing.T) {
	handler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}

	port := startSOATestServer(
		t, "udp", "127.0.0.1:0", handler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	record, err := lookupSOAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if record != nil {
		t.Errorf("expected no record, got %+v", record)
	}
}

func TestLookupSOAFromServersNoServers(t *testing.T) {
	_, err := lookupSOAFromServers(
		context.Background(),
		"example.com",
		nil,
		"53",
	)

	if err == nil {
		t.Fatal("expected error for missing DNS servers")
	}

	if !strings.Contains(err.Error(), "no DNS servers") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLookupSOAFromServersCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := lookupSOAFromServers(
		ctx,
		"example.com",
		[]string{"127.0.0.1"},
		"53",
	)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestLookupSOAFromServersRetryDNSFailure(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{
			name: "SERVFAIL",
			code: mdns.RcodeServerFailure,
		},
		{
			name: "REFUSED",
			code: mdns.RcodeRefused,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var firstCalled atomic.Bool
			var secondCalled atomic.Bool

			firstHandler := func(
				w mdns.ResponseWriter,
				request *mdns.Msg,
			) {
				firstCalled.Store(true)

				response := new(mdns.Msg)
				response.SetRcode(request, tt.code)

				if err := w.WriteMsg(response); err != nil {
					t.Errorf("write first DNS response: %v", err)
				}
			}

			secondHandler := func(
				w mdns.ResponseWriter,
				request *mdns.Msg,
			) {
				secondCalled.Store(true)

				response := new(mdns.Msg)
				response.SetReply(request)
				response.Answer = []mdns.RR{testSOARecord()}

				if err := w.WriteMsg(response); err != nil {
					t.Errorf("write second DNS response: %v", err)
				}
			}

			port := startSOATestServer(
				t,
				"udp",
				"127.0.0.1:0",
				firstHandler,
			)

			startSOATestServer(
				t,
				"udp",
				net.JoinHostPort("127.0.0.2", port),
				secondHandler,
			)

			ctx, cancel := context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
			defer cancel()

			record, err := lookupSOAFromServers(
				ctx,
				"example.com",
				[]string{"127.0.0.1", "127.0.0.2"},
				port,
			)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if record == nil {
				t.Fatal("expected SOA record from second server")
			}

			if !firstCalled.Load() {
				t.Error("expected first DNS server to be queried")
			}

			if !secondCalled.Load() {
				t.Error("expected fallback to second DNS server")
			}

			if record.NS != "ns1.example.com." {
				t.Errorf("unexpected nameserver: %q", record.NS)
			}

			if record.Serial != 2026111201 {
				t.Errorf("unexpected serial: %d", record.Serial)
			}
		})
	}
}
