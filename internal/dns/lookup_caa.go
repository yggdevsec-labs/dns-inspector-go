package dns

import (
	"context"
	"errors"
	"strings"
)

// CAARecord represents a DNS Certificate Authority Authorization record.
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// CAAResolver defines the DNS resolution method for CAA lookups.
type CAAResolver interface {
	LookupCAA(
		ctx context.Context,
		domain string,
	) ([]CAARecord, error)
}

// LookupCAA retrieves CAA records for a domain.
func LookupCAA(
	ctx context.Context,
	resolver CAAResolver,
	domain string,
) ([]CAARecord, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupCAA(ctx, domain)
}
