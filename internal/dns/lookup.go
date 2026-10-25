package dns

import (
	"context"
	"errors"
	"net"
	"strings"
)

// IPResolver defines the DNS resolution method used for IP lookups.
type IPResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// LookupA retrieves IPv4 addresses associated with a domain.
func LookupA(ctx context.Context, resolver IPResolver, domain string) ([]net.IP, error) {
	return lookupIP(ctx, resolver, domain, "ip4")
}

// LookupAAAA retrieves IPv6 addresses associated with a domain.
func LookupAAAA(ctx context.Context, resolver IPResolver, domain string) ([]net.IP, error) {
	return lookupIP(ctx, resolver, domain, "ip6")
}

func lookupIP(ctx context.Context, resolver IPResolver, domain, network string) ([]net.IP, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("domain must not be empty")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupIP(ctx, network, domain)
}
