package dns_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockNSResolver struct {
	lookup func(context.Context, string) ([]*net.NS, error)
}

func (m mockNSResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	return m.lookup(ctx, name)
}

func TestLookupNSSuccess(t *testing.T) {
	ctx := context.Background()

	resolver := mockNSResolver{
		lookup: func(gotCtx context.Context, domain string) ([]*net.NS, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if domain != "example.com" {
				t.Errorf("unexpected domain: %q", domain)
			}

			return []*net.NS{
				{Host: "ns1.example.com."},
				{Host: "ns2.example.com."},
			}, nil
		},
	}

	records, err := dns.LookupNS(ctx, resolver, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 NS records, got %d", len(records))
	}

	if records[0].Host != "ns1.example.com." {
		t.Errorf("unexpected first NS record: %s", records[0].Host)
	}

	if records[1].Host != "ns2.example.com." {
		t.Errorf("unexpected second NS record: %s", records[1].Host)
	}
}

func TestLookupNSInvalidDomain(t *testing.T) {
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
			resolver := mockNSResolver{
				lookup: func(context.Context, string) ([]*net.NS, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupNS(
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

func TestLookupNSNilResolver(t *testing.T) {
	_, err := dns.LookupNS(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupNSResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockNSResolver{
		lookup: func(context.Context, string) ([]*net.NS, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupNS(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupNSNoRecords(t *testing.T) {
	resolver := mockNSResolver{
		lookup: func(context.Context, string) ([]*net.NS, error) {
			return nil, nil
		},
	}

	records, err := dns.LookupNS(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no NS records, got %d", len(records))
	}
}
