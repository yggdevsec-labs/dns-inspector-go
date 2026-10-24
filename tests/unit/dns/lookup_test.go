package dns_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockResolver struct {
	lookup func(context.Context, string, string) ([]net.IP, error)
}

func (m mockResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	return m.lookup(ctx, network, host)
}

func TestLookupASuccess(t *testing.T) {
	expected := net.ParseIP("192.0.2.1")
	ctx := context.Background()

	resolver := mockResolver{
		lookup: func(gotCtx context.Context, network, host string) ([]net.IP, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if network != "ip4" {
				t.Errorf("expected ip4, got %q", network)
			}
			if host != "example.com" {
				t.Errorf("unexpected domain: %q", host)
			}
			return []net.IP{expected}, nil
		},
	}

	addresses, err := dns.LookupA(ctx, resolver, "example.com")
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

func TestLookupAInvalidDomain(t *testing.T) {
	domains := []string{"", " ", "\t\n"}

	for _, domain := range domains {
		t.Run("invalid_domain", func(t *testing.T) {
			resolver := mockResolver{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupA(context.Background(), resolver, domain)
			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestLookupANilResolver(t *testing.T) {
	_, err := dns.LookupA(context.Background(), nil, "example.com")

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupAResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupA(context.Background(), resolver, "example.com")

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupANoRecords(t *testing.T) {
	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, nil
		},
	}

	addresses, err := dns.LookupA(context.Background(), resolver, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(addresses) != 0 {
		t.Errorf("expected no addresses, got %d", len(addresses))
	}
}
