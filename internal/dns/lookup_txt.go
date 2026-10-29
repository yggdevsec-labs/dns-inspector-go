package dns

import (
	"context"
	"errors"
	"strings"
)

// TXTResolver defines the DNS resolution method for TXT lookups.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// LookupTXT retrieves TXT records for a domain.
func LookupTXT(ctx context.Context, resolver TXTResolver, domain string) ([]string, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupTXT(ctx, domain)
}
