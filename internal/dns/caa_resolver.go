package dns

import (
	"context"
	"errors"
	"fmt"
	"net"

	mdns "github.com/miekg/dns"
)

// LookupCAA queries the configured DNS servers for CAA records.
func (r *DNSResolver) LookupCAA(
	ctx context.Context,
	domain string,
) ([]CAARecord, error) {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read DNS configuration: %w", err)
	}

	return lookupCAAFromServers(
		ctx,
		domain,
		config.Servers,
		config.Port,
	)
}

// lookupCAAFromServers queries explicitly configured DNS servers.
func lookupCAAFromServers(
	ctx context.Context,
	domain string,
	servers []string,
	port string,
) ([]CAARecord, error) {
	if len(servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}

	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(domain), mdns.TypeCAA)

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

		if response.Truncated {
			lastErr = fmt.Errorf("truncated TCP DNS response from %s", address)
			continue
		}

		if response.Rcode != mdns.RcodeSuccess {
			responseErr := fmt.Errorf(
				"CAA DNS response: %s",
				mdns.RcodeToString[response.Rcode],
			)

			if response.Rcode == mdns.RcodeServerFailure ||
				response.Rcode == mdns.RcodeRefused {
				lastErr = responseErr
				continue
			}

			return nil, responseErr
		}

		var records []CAARecord

		for _, answer := range response.Answer {
			caa, ok := answer.(*mdns.CAA)
			if !ok {
				continue
			}

			records = append(records, CAARecord{
				Flag:  caa.Flag,
				Tag:   caa.Tag,
				Value: caa.Value,
			})
		}

		return records, nil
	}

	return nil, fmt.Errorf("CAA lookup failed: %w", lastErr)
}
