package dns

import (
	"context"
	"errors"
	"strings"
)

// CNAMEResolver defines the DNS resolution method for canonical names.
type CNAMEResolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// LookupCNAME retrieves the canonical name for a domain.
// A successful result does not necessarily indicate a CNAME record exists.
func LookupCNAME(ctx context.Context, resolver CNAMEResolver, domain string) (string, error) {
	if strings.TrimSpace(domain) == "" {
		return "", errors.New("domain must not be empty")
	}

	if resolver == nil {
		return "", errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupCNAME(ctx, domain)
}
