package dns_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

func TestLookupAAAASuccess(t *testing.T) {
	ctx := context.Background()
	expected := net.ParseIP("2001:db8::1")

	resolver := mockResolver{
		lookup: func(gotCtx context.Context, network, host string) ([]net.IP, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if network != "ip6" {
				t.Errorf("expected ip6, got %q", network)
			}
			if host != "example.com" {
				t.Errorf("unexpected domain: %q", host)
			}

			return []net.IP{expected}, nil
		},
	}

	addresses, err := dns.LookupAAAA(ctx, resolver, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addresses))
	}

	if !addresses[0].Equal(expected) {
		t.Errorf("expected %s, got %s", expected, addresses[0])
	}
}

func TestLookupAAAAInvalidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"empty", ""},
		{"space", " "},
		{"whitespace", "\t\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := mockResolver{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupAAAA(
				context.Background(),
				resolver,
				tt.domain,
			)

			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestLookupAAAANilResolver(t *testing.T) {
	_, err := dns.LookupAAAA(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupAAAAResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupAAAA(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupAAAANoRecords(t *testing.T) {
	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, nil
		},
	}

	addresses, err := dns.LookupAAAA(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 0 {
		t.Errorf("expected no addresses, got %d", len(addresses))
	}
}
