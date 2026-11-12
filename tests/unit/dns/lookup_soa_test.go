package dns_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockSOAResolver struct {
	lookup func(context.Context, string) (*dns.SOARecord, error)
}

func (m mockSOAResolver) LookupSOA(
	ctx context.Context,
	domain string,
) (*dns.SOARecord, error) {
	return m.lookup(ctx, domain)
}

func TestLookupSOASuccess(t *testing.T) {
	ctx := context.Background()
	domain := "example.com"

	expected := &dns.SOARecord{
		NS:      "ns1.example.com.",
		MBox:    "hostmaster.example.com.",
		Serial:  2026111201,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		MinTTL:  3600,
	}

	resolver := mockSOAResolver{
		lookup: func(
			gotCtx context.Context,
			gotDomain string,
		) (*dns.SOARecord, error) {
			if gotCtx != ctx {
				t.Error("unexpected context")
			}

			if gotDomain != domain {
				t.Errorf("expected domain %q, got %q",
					domain, gotDomain)
			}

			return expected, nil
		},
	}

	record, err := dns.LookupSOA(ctx, resolver, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if record == nil {
		t.Fatal("expected SOA record, got nil")
	}

	if *record != *expected {
		t.Errorf("expected %+v, got %+v", expected, record)
	}
}

func TestLookupSOAInvalidDomain(t *testing.T) {
	domains := []string{
		"",
		" ",
		"\t\n",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			resolver := mockSOAResolver{
				lookup: func(
					context.Context,
					string,
				) (*dns.SOARecord, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupSOA(
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

func TestLookupSOANilResolver(t *testing.T) {
	_, err := dns.LookupSOA(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupSOAResolverError(t *testing.T) {
	expectedErr := errors.New("DNS timeout")

	resolver := mockSOAResolver{
		lookup: func(
			context.Context,
			string,
		) (*dns.SOARecord, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupSOA(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupSOANoRecord(t *testing.T) {
	resolver := mockSOAResolver{
		lookup: func(
			context.Context,
			string,
		) (*dns.SOARecord, error) {
			return nil, nil
		},
	}

	record, err := dns.LookupSOA(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if record != nil {
		t.Errorf("expected no SOA record, got %+v", record)
	}
}
