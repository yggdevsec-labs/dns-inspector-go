package dns

import (
	"context"
	"errors"
	"net"
	"strings"
)

// MXResolver defines the DNS resolution method for MX lookups.
type MXResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// LookupMX retrieves mail exchange records for a domain.
func LookupMX(ctx context.Context, resolver MXResolver, domain string) ([]*net.MX, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupMX(ctx, domain)
}
