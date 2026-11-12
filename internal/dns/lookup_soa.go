package dns

import (
	"context"
	"errors"
	"strings"
)

// SOARecord represents the fields of a DNS SOA record.
type SOARecord struct {
	NS      string
	MBox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

// SOAResolver defines the DNS resolution method for SOA lookups.
type SOAResolver interface {
	LookupSOA(
		ctx context.Context,
		domain string,
	) (*SOARecord, error)
}

// LookupSOA retrieves the SOA record for a DNS zone.
func LookupSOA(
	ctx context.Context,
	resolver SOAResolver,
	domain string,
) (*SOARecord, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupSOA(ctx, domain)
}
