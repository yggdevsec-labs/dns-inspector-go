package dns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockTXTResolver struct {
	lookup func(context.Context, string) ([]string, error)
}

func (m mockTXTResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	return m.lookup(ctx, name)
}

func TestLookupTXTSuccess(t *testing.T) {
	ctx := context.Background()

	expected := []string{
		"v=spf1 include:_spf.example.com ~all",
		"google-site-verification=test123",
	}

	resolver := mockTXTResolver{
		lookup: func(gotCtx context.Context, domain string) ([]string, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if domain != "example.com" {
				t.Errorf("unexpected domain: %q", domain)
			}

			return expected, nil
		},
	}

	records, err := dns.LookupTXT(ctx, resolver, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != len(expected) {
		t.Fatalf("expected %d TXT records, got %d", len(expected), len(records))
	}

	for i, record := range records {
		if record != expected[i] {
			t.Errorf("expected %q, got %q", expected[i], record)
		}
	}
}

func TestLookupTXTInvalidDomain(t *testing.T) {
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
			resolver := mockTXTResolver{
				lookup: func(context.Context, string) ([]string, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupTXT(
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

func TestLookupTXTNilResolver(t *testing.T) {
	_, err := dns.LookupTXT(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupTXTResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockTXTResolver{
		lookup: func(context.Context, string) ([]string, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupTXT(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupTXTNoRecords(t *testing.T) {
	resolver := mockTXTResolver{
		lookup: func(context.Context, string) ([]string, error) {
			return nil, nil
		},
	}

	records, err := dns.LookupTXT(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no TXT records, got %d", len(records))
	}
}
