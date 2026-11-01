package dns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockCNAMEResolver struct {
	lookup func(context.Context, string) (string, error)
}

func (m mockCNAMEResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	return m.lookup(ctx, host)
}

func TestLookupCNAMESuccess(t *testing.T) {
	ctx := context.Background()
	expected := "target.example.com."

	resolver := mockCNAMEResolver{
		lookup: func(gotCtx context.Context, domain string) (string, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}
			if domain != "alias.example.com" {
				t.Errorf("unexpected domain: %q", domain)
			}

			return expected, nil
		},
	}

	result, err := dns.LookupCNAME(ctx, resolver, "alias.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestLookupCNAMECanonicalName(t *testing.T) {
	expected := "example.com."

	resolver := mockCNAMEResolver{
		lookup: func(context.Context, string) (string, error) {
			return expected, nil
		},
	}

	result, err := dns.LookupCNAME(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestLookupCNAMEInvalidDomain(t *testing.T) {
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
			resolver := mockCNAMEResolver{
				lookup: func(context.Context, string) (string, error) {
					t.Fatal("resolver must not be called")
					return "", nil
				},
			}

			_, err := dns.LookupCNAME(
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

func TestLookupCNAMENilResolver(t *testing.T) {
	_, err := dns.LookupCNAME(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupCNAMEResolverError(t *testing.T) {
	expectedErr := errors.New("DNS lookup failed")

	resolver := mockCNAMEResolver{
		lookup: func(context.Context, string) (string, error) {
			return "", expectedErr
		},
	}

	_, err := dns.LookupCNAME(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}
