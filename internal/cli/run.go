package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

const lookupTimeout = 5 * time.Second

// Run executes a DNS lookup and returns an exit code.
func Run(args []string, output, errorOutput io.Writer, resolver dns.IPResolver) int {
	recordType := dns.RecordTypeA
	var domain string

	switch {
	case len(args) == 1:
		domain = args[0]
	case len(args) == 3 && args[0] == "--type":
		recordType = dns.RecordType(strings.ToUpper(args[1]))
		domain = args[2]
	default:
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	if strings.TrimSpace(domain) == "" {
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	if recordType != dns.RecordTypeA && recordType != dns.RecordTypeAAAA {
		_, _ = fmt.Fprintf(
			errorOutput,
			"Unsupported record type: use %s or %s\n",
			dns.RecordTypeA,
			dns.RecordTypeAAAA,
		)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	var addresses []net.IP
	var err error

	if recordType == dns.RecordTypeAAAA {
		addresses, err = dns.LookupAAAA(ctx, resolver, domain)
	} else {
		addresses, err = dns.LookupA(ctx, resolver, domain)
	}

	if err != nil {
		_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
		return 1
	}

	if len(addresses) == 0 {
		_, _ = fmt.Fprintf(errorOutput, "No %s records found\n", recordType)
		return 1
	}

	for _, address := range addresses {
		if _, err := fmt.Fprintln(output, address); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
			return 1
		}
	}

	return 0
}
