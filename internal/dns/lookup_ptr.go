package dns

import (
	"context"
	"errors"
	"net"
	"strings"
)

// PTRResolver defines the DNS resolution method for reverse lookups.
type PTRResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// LookupPTR retrieves hostnames associated with an IP address.
func LookupPTR(
	ctx context.Context,
	resolver PTRResolver,
	ip string,
) ([]string, error) {
	if strings.TrimSpace(ip) == "" {
		return nil, errors.New("IP address must not be empty")
	}

	if net.ParseIP(ip) == nil {
		return nil, errors.New("invalid IP address")
	}

	if resolver == nil {
		return nil, errors.New("DNS resolver must not be nil")
	}

	return resolver.LookupAddr(ctx, ip)
}
