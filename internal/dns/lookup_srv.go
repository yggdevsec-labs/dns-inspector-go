package dns

import (
	"context"
	"errors"
	"net"
	"strings"
)

// SRVResolver defines the DNS resolution method for SRV lookups.
type SRVResolver interface {
	LookupSRV(
		ctx context.Context,
		service, proto, name string,
	) (string, []*net.SRV, error)
}

// LookupSRV retrieves SRV records for a DNS service name.
func LookupSRV(
	ctx context.Context,
	resolver SRVResolver,
	domain string,
) ([]*net.SRV, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	_, records, err := resolver.LookupSRV(ctx, "", "", domain)
	return records, err
}
