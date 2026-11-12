package dns

import (
	"context"
	"errors"
	"fmt"
	"net"

	mdns "github.com/miekg/dns"
)

// DNSResolver extends Go's standard resolver with SOA lookups.
type DNSResolver struct {
	*net.Resolver
}

// NewDNSResolver creates a resolver with SOA support.
func NewDNSResolver() *DNSResolver {
	return &DNSResolver{
		Resolver: net.DefaultResolver,
	}
}

// LookupSOA queries the configured DNS servers for an SOA record.

func (r *DNSResolver) LookupSOA(
	ctx context.Context,
	domain string,
) (*SOARecord, error) {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read DNS configuration: %w", err)
	}

	return lookupSOAFromServers(
		ctx,
		domain,
		config.Servers,
		config.Port,
	)
}

// lookupSOAFromServers queries explicitly configured DNS servers.
func lookupSOAFromServers(
	ctx context.Context,
	domain string,
	servers []string,
	port string,
) (*SOARecord, error) {
	if len(servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}

	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(domain), mdns.TypeSOA)

	var lastErr error

	for _, server := range servers {
		address := net.JoinHostPort(server, port)

		client := &mdns.Client{Net: "udp"}
		response, _, err := client.ExchangeContext(
			ctx,
			request,
			address,
		)

		if err == nil && response != nil && response.Truncated {
			client.Net = "tcp"
			response, _, err = client.ExchangeContext(
				ctx,
				request,
				address,
			)
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			lastErr = err
			continue
		}

		if response == nil {
			lastErr = errors.New("empty DNS response")
			continue
		}

		if response.Rcode != mdns.RcodeSuccess {
			responseErr := fmt.Errorf(
				"SOA DNS response: %s",
				mdns.RcodeToString[response.Rcode],
			)

			if response.Rcode == mdns.RcodeServerFailure ||
				response.Rcode == mdns.RcodeRefused {
				lastErr = responseErr
				continue
			}

			return nil, responseErr
		}

		for _, answer := range response.Answer {
			soa, ok := answer.(*mdns.SOA)
			if !ok {
				continue
			}

			return &SOARecord{
				NS:      soa.Ns,
				MBox:    soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				MinTTL:  soa.Minttl,
			}, nil
		}

		return nil, nil
	}

	return nil, fmt.Errorf("SOA lookup failed: %w", lastErr)
}
