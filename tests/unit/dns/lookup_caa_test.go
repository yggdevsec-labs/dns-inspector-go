package dns_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockCAAResolver struct {
	lookup func(context.Context, string) ([]dns.CAARecord, error)
}

func (m mockCAAResolver) LookupCAA(
	ctx context.Context,
	domain string,
) ([]dns.CAARecord, error) {
	return m.lookup(ctx, domain)
}

func TestLookupCAASuccess(t *testing.T) {
	ctx := context.Background()
	domain := "example.com"

	expected := []dns.CAARecord{
		{
			Flag:  0,
			Tag:   "issue",
			Value: "letsencrypt.org",
		},
		{
			Flag:  0,
			Tag:   "issuewild",
			Value: "digicert.com",
		},
		{
			Flag:  0,
			Tag:   "iodef",
			Value: "mailto:security@example.com",
		},
		{
			Flag:  128,
			Tag:   "issue",
			Value: "example-ca.com",
		},
	}

	resolver := mockCAAResolver{
		lookup: func(
			gotCtx context.Context,
			gotDomain string,
		) ([]dns.CAARecord, error) {
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

	records, err := dns.LookupCAA(ctx, resolver, domain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(records, expected) {
		t.Errorf("expected %+v, got %+v", expected, records)
	}
}

func TestLookupCAAInvalidDomain(t *testing.T) {
	domains := []string{
		"",
		" ",
		"\t\n",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			resolver := mockCAAResolver{
				lookup: func(
					context.Context,
					string,
				) ([]dns.CAARecord, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			_, err := dns.LookupCAA(
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

func TestLookupCAANilResolver(t *testing.T) {
	_, err := dns.LookupCAA(
		context.Background(),
		nil,
		"example.com",
	)

	if err == nil {
		t.Error("expected error for nil resolver")
	}
}

func TestLookupCAAResolverError(t *testing.T) {
	expectedErr := errors.New("DNS timeout")

	resolver := mockCAAResolver{
		lookup: func(
			context.Context,
			string,
		) ([]dns.CAARecord, error) {
			return nil, expectedErr
		},
	}

	_, err := dns.LookupCAA(
		context.Background(),
		resolver,
		"example.com",
	)

	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}
}

func TestLookupCAANoRecords(t *testing.T) {
	resolver := mockCAAResolver{
		lookup: func(
			context.Context,
			string,
		) ([]dns.CAARecord, error) {
			return nil, nil
		},
	}

	records, err := dns.LookupCAA(
		context.Background(),
		resolver,
		"example.com",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("expected no CAA records, got %+v", records)
	}
}
