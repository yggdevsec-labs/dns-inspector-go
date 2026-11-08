package dns_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockSRVResolver struct {
	lookup func(context.Context, string, string, string) (string, []*net.SRV, error)
}

func (m mockSRVResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return m.lookup(ctx, service, proto, name)
}

func TestLookupSRVSuccess(t *testing.T) {
	ctx := context.Background()
	domain := "_sip._tcp.example.com"

	expected := []*net.SRV{
		{
			Target:   "sip1.example.com.",
			Port:     5060,
			Priority: 10,
			Weight:   60,
		},
		{
			Target:   "sip2.example.com.",
			Port:     5060,
			Priority: 20,
			Weight:   40,
		},
	}

	resolver := mockSRVResolver{
		lookup: func(
			gotCtx context.Context,
			service, proto, name string,
		) (string, []*net.SRV, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}

			if service != "" || proto != "" {
				t.Errorf("expected empty service and proto, got %q and %q",
					service, proto)
			}

			if name != domain {
				t.Errorf("expected domain %q, got %q", domain, name)
			}

			return "", expected, nil
		},
	}

	records, err := dns.LookupSRV(ctx, resolver, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != len(expected) {
		t.Fatalf("expected %d records, got %d", len(expected), len(records))
	}

	for i, record := range records {
		if *record != *expected[i] {
			t.Errorf("record %d: expected %+v, got %+v",
				i, expected[i], record)
		}
	}
}

func TestLookupSRVInvalidDomain(t *testing.T) {
	domains := []string{"", " ", "\t\n"}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			resolver := mockSRVResolver{
				lookup: func(
					context.Context, string, string, string,
				) (string, []*net.SRV, error) {
					t.Fatal("resolver must not be called")
					return "", nil, nil
				},
			}

			_, err := dns.LookupSRV(
				context.Background(),
				resolver,
				domain,
			)

			if err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestLookupSRVNilResolver(t *testing.T) {
	_, err := dns.LookupSRV(
		context.Background(),
		nil,
		"_sip._tcp.example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupSRVResolverError(t *testing.T) {
	expectedErr := errors.New("DNS timeout")

	resolver := mockSRVResolver{
		lookup: func(
			context.Context, string, string, string,
		) (string, []*net.SRV, error) {
			return "", nil, expectedErr
		},
	}

	_, err := dns.LookupSRV(
		context.Background(),
		resolver,
		"_sip._tcp.example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupSRVNoRecords(t *testing.T) {
	resolver := mockSRVResolver{
		lookup: func(
			context.Context, string, string, string,
		) (string, []*net.SRV, error) {
			return "", nil, nil
		},
	}

	records, err := dns.LookupSRV(
		context.Background(),
		resolver,
		"_sip._tcp.example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no records, got %d", len(records))
	}
}
