package dns_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockPTRResolver struct {
	lookup func(context.Context, string) ([]string, error)
}

func (m mockPTRResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return m.lookup(ctx, addr)
}

func TestLookupPTRSuccess(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected []string
	}{
		{
			name:     "IPv4",
			ip:       "8.8.8.8",
			expected: []string{"dns.google."},
		},
		{
			name:     "IPv6",
			ip:       "2001:4860:4860::8888",
			expected: []string{"dns.google."},
		},
		{
			name:     "multiple hostnames",
			ip:       "192.0.2.1",
			expected: []string{"host1.example.com.", "host2.example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			resolver := mockPTRResolver{
				lookup: func(
					gotCtx context.Context,
					addr string,
				) ([]string, error) {
					if gotCtx != ctx {
						t.Error("unexpected context")
					}

					if addr != tt.ip {
						t.Errorf("expected address %q, got %q", tt.ip, addr)
					}

					return tt.expected, nil
				},
			}

			records, err := dns.LookupPTR(ctx, resolver, tt.ip)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(records, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, records)
			}
		})
	}
}

func TestLookupPTRInvalidIP(t *testing.T) {
	tests := []string{
		"",
		" ",
		"\t\n",
		"example.com",
		"999.999.999.999",
		"192.0.2",
		"8.8.8.8\n",
		"8.8.8.8\x1b[31m",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			resolver := mockPTRResolver{
				lookup: func(context.Context, string) ([]string, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupPTR(
				context.Background(),
				resolver,
				ip,
			)

			if err == nil {
				t.Errorf("expected validation error for %q", ip)
			}
		})
	}
}

func TestLookupPTRNilResolver(t *testing.T) {
	_, err := dns.LookupPTR(
		context.Background(),
		nil,
		"8.8.8.8",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupPTRResolverError(t *testing.T) {
	expectedErr := errors.New("DNS timeout")

	resolver := mockPTRResolver{
		lookup: func(context.Context, string) ([]string, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupPTR(
		context.Background(),
		resolver,
		"8.8.8.8",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupPTRNoRecords(t *testing.T) {
	resolver := mockPTRResolver{
		lookup: func(context.Context, string) ([]string, error) {
			return nil, nil
		},
	}

	records, err := dns.LookupPTR(
		context.Background(),
		resolver,
		"8.8.8.8",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no records, got %v", records)
	}
}
