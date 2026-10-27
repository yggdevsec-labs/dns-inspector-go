package dns_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockMXResolver struct {
	lookup func(context.Context, string) ([]*net.MX, error)
}

func (m mockMXResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	return m.lookup(ctx, name)
}

func TestLookupMXSuccess(t *testing.T) {
	ctx := context.Background()

	resolver := mockMXResolver{
		lookup: func(gotCtx context.Context, domain string) ([]*net.MX, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if domain != "example.com" {
				t.Errorf("unexpected domain: %q", domain)
			}

			return []*net.MX{
				{Host: "mail.example.com.", Pref: 10},
				{Host: "backup.example.com.", Pref: 20},
			}, nil
		},
	}

	records, err := dns.LookupMX(ctx, resolver, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 MX records, got %d", len(records))
	}

	if records[0].Host != "mail.example.com." || records[0].Pref != 10 {
		t.Errorf("unexpected first MX record: %+v", records[0])
	}

	if records[1].Host != "backup.example.com." || records[1].Pref != 20 {
		t.Errorf("unexpected second MX record: %+v", records[1])
	}
}

func TestLookupMXInvalidDomain(t *testing.T) {
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
			resolver := mockMXResolver{
				lookup: func(context.Context, string) ([]*net.MX, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupMX(
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

func TestLookupMXNilResolver(t *testing.T) {
	_, err := dns.LookupMX(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupMXResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockMXResolver{
		lookup: func(context.Context, string) ([]*net.MX, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupMX(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupMXNoRecords(t *testing.T) {
	resolver := mockMXResolver{
		lookup: func(context.Context, string) ([]*net.MX, error) {
			return nil, nil
		},
	}

	records, err := dns.LookupMX(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no MX records, got %d", len(records))
	}
}
