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

// startCAATestServer starts a local DNS server for CAA tests.
func startCAATestServer(
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
		t.Fatalf("unsupported network: %s", network)
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

func testCAARecords() []mdns.RR {
	return []mdns.RR{
		&mdns.CAA{
			Hdr: mdns.RR_Header{
				Name:   "example.com.",
				Rrtype: mdns.TypeCAA,
				Class:  mdns.ClassINET,
				Ttl:    300,
			},
			Flag:  0,
			Tag:   "issue",
			Value: "letsencrypt.org",
		},
		&mdns.CAA{
			Hdr: mdns.RR_Header{
				Name:   "example.com.",
				Rrtype: mdns.TypeCAA,
				Class:  mdns.ClassINET,
				Ttl:    300,
			},
			Flag:  0,
			Tag:   "issuewild",
			Value: "digicert.com",
		},
		&mdns.CAA{
			Hdr: mdns.RR_Header{
				Name:   "example.com.",
				Rrtype: mdns.TypeCAA,
				Class:  mdns.ClassINET,
				Ttl:    300,
			},
			Flag:  128,
			Tag:   "iodef",
			Value: "mailto:security@example.com",
		},
	}
}

func TestLookupCAAFromServersUDP(t *testing.T) {
	handler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		if len(request.Question) != 1 {
			t.Error("expected one DNS question")
			return
		}

		question := request.Question[0]
		if question.Name != "example.com." ||
			question.Qtype != mdns.TypeCAA ||
			question.Qclass != mdns.ClassINET {
			t.Errorf("unexpected DNS question: %+v", question)
		}

		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = testCAARecords()

		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write DNS response: %v", err)
		}
	}

	port := startCAATestServer(
		t, "udp", "127.0.0.1:0", handler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	records, err := lookupCAAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []CAARecord{
		{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
		{Flag: 0, Tag: "issuewild", Value: "digicert.com"},
		{
			Flag:  128,
			Tag:   "iodef",
			Value: "mailto:security@example.com",
		},
	}

	if !reflect.DeepEqual(records, expected) {
		t.Errorf("expected %+v, got %+v", expected, records)
	}
}

func TestLookupCAAFromServersTCPFallback(t *testing.T) {
	var udpCalled atomic.Bool
	var tcpCalled atomic.Bool

	tcpHandler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		tcpCalled.Store(true)

		response := new(mdns.Msg)
		response.SetReply(request)
		response.Answer = testCAARecords()

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

	port := startCAATestServer(
		t, "tcp", "127.0.0.1:0", tcpHandler,
	)

	startCAATestServer(
		t,
		"udp",
		net.JoinHostPort("127.0.0.1", port),
		udpHandler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	records, err := lookupCAAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 3 {
		t.Errorf("expected 3 CAA records, got %d", len(records))
	}

	if !udpCalled.Load() {
		t.Error("expected UDP lookup")
	}

	if !tcpCalled.Load() {
		t.Error("expected TCP fallback")
	}
}

func TestLookupCAAFromServersTruncatedTCP(t *testing.T) {
	truncatedHandler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		response.Truncated = true
		response.Answer = testCAARecords()[:1]
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write truncated DNS response: %v", err)
		}
	}
	port := startCAATestServer(t, "tcp", "127.0.0.1:0", truncatedHandler)
	startCAATestServer(t, "udp", net.JoinHostPort("127.0.0.1", port), truncatedHandler)

	t.Run("no next server", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		records, err := lookupCAAFromServers(ctx, "example.com", []string{"127.0.0.1"}, port)
		if err == nil || !strings.Contains(err.Error(), "truncated TCP DNS response") {
			t.Errorf("expected TCP truncation error, got %v", err)
		}
		if len(records) != 0 {
			t.Errorf("expected no partial CAA records, got %+v", records)
		}
	})

	t.Run("next server answers", func(t *testing.T) {
		completeHandler := func(w mdns.ResponseWriter, request *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(request)
			response.Answer = testCAARecords()[1:]
			if err := w.WriteMsg(response); err != nil {
				t.Errorf("write complete DNS response: %v", err)
			}
		}
		startCAATestServer(t, "udp", net.JoinHostPort("127.0.0.2", port), completeHandler)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		records, err := lookupCAAFromServers(ctx, "example.com", []string{"127.0.0.1", "127.0.0.2"}, port)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []CAARecord{
			{Tag: "issuewild", Value: "digicert.com"},
			{Flag: 128, Tag: "iodef", Value: "mailto:security@example.com"},
		}
		if !reflect.DeepEqual(records, want) {
			t.Errorf("expected records from the next server: %+v, got %+v", want, records)
		}
	})
}

func TestLookupCAAFromServersFailover(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{"SERVFAIL", mdns.RcodeServerFailure},
		{"REFUSED", mdns.RcodeRefused},
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
				_ = w.WriteMsg(response)
			}

			secondHandler := func(
				w mdns.ResponseWriter,
				request *mdns.Msg,
			) {
				secondCalled.Store(true)

				response := new(mdns.Msg)
				response.SetReply(request)
				response.Answer = testCAARecords()
				_ = w.WriteMsg(response)
			}

			port := startCAATestServer(
				t, "udp", "127.0.0.1:0", firstHandler,
			)

			startCAATestServer(
				t,
				"udp",
				net.JoinHostPort("127.0.0.2", port),
				secondHandler,
			)

			ctx, cancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			defer cancel()

			records, err := lookupCAAFromServers(
				ctx,
				"example.com",
				[]string{"127.0.0.1", "127.0.0.2"},
				port,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !firstCalled.Load() {
				t.Error("expected first DNS server to be queried")
			}

			if !secondCalled.Load() {
				t.Error("expected fallback to second DNS server")
			}

			if len(records) != 3 {
				t.Errorf("expected 3 CAA records, got %d",
					len(records))
			}
		})
	}
}

func TestLookupCAAFromServersDNSFailure(t *testing.T) {
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

			port := startCAATestServer(
				t, "udp", "127.0.0.1:0", handler,
			)

			ctx, cancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			defer cancel()

			_, err := lookupCAAFromServers(
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

func TestLookupCAAFromServersNoRecords(t *testing.T) {
	handler := func(w mdns.ResponseWriter, request *mdns.Msg) {
		response := new(mdns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}

	port := startCAATestServer(
		t, "udp", "127.0.0.1:0", handler,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	records, err := lookupCAAFromServers(
		ctx, "example.com", []string{"127.0.0.1"}, port,
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no CAA records, got %+v", records)
	}
}

func TestLookupCAAFromServersNoServers(t *testing.T) {
	_, err := lookupCAAFromServers(
		context.Background(),
		"example.com",
		nil,
		"53",
	)

	if err == nil {
		t.Fatal("expected error for missing DNS servers")
	}
}

func TestLookupCAAFromServersCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := lookupCAAFromServers(
		ctx,
		"example.com",
		[]string{"127.0.0.1"},
		"53",
	)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
