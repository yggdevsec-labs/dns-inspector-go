package dns

import (
	"context"
	"errors"
	"net"
	"strings"
)

// NSResolver defines the DNS resolution method for NS lookups.
type NSResolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// LookupNS retrieves name server records for a domain.
func LookupNS(ctx context.Context, resolver NSResolver, domain string) ([]*net.NS, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupNS(ctx, domain)
}
