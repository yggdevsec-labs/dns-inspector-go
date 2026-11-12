package cli

import (
	"context"
	"fmt"
	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
	"io"
	"net"
	"strings"
	"time"
)

const lookupTimeout = 5 * time.Second

// Run executes a DNS lookup and returns an exit code.
func Run(args []string, output, errorOutput io.Writer, resolver dns.IPResolver) int {
	opts, ok := parseArgs(args)
	if !ok {
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	if strings.TrimSpace(opts.domain) == "" {
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	switch opts.recordType {
	case dns.RecordTypeA, dns.RecordTypeAAAA, dns.RecordTypeMX,
		dns.RecordTypeNS, dns.RecordTypeTXT, dns.RecordTypeCNAME,
		dns.RecordTypePTR,
		dns.RecordTypeSRV:
	default:
		_, _ = fmt.Fprintln(errorOutput,
			"Unsupported record type: use A, AAAA, MX, NS, TXT, CNAME, SRV or PTR")
		return 2
	}

	if opts.recordType == dns.RecordTypePTR {
		if net.ParseIP(opts.domain) == nil {
			_, _ = fmt.Fprintln(errorOutput, "Invalid IP address")
			return 2
		}
	} else {
		if err := dns.ValidateDomain(opts.domain); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Invalid domain: %v\n", err)
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	records, err := lookupRecords(ctx, resolver, opts.recordType, opts.domain)
	if err != nil {
		_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
		return 1
	}

	if len(records) == 0 {
		if opts.recordType == dns.RecordTypeCNAME {
			_, _ = fmt.Fprintln(errorOutput, "No CNAME alias found")
		} else {
			_, _ = fmt.Fprintf(errorOutput, "No %s records found\n", opts.recordType)
		}
		return 1
	}

	return writeOutput(output, errorOutput, opts, records)

}
