package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
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
		dns.RecordTypeNS, dns.RecordTypeTXT, dns.RecordTypeCNAME:
	default:
		_, _ = fmt.Fprintln(errorOutput,
			"Unsupported record type: use A, AAAA, MX, NS, TXT or CNAME")
		return 2
	}

	if err := dns.ValidateDomain(opts.domain); err != nil {
		_, _ = fmt.Fprintf(errorOutput, "Invalid domain: %v\n", err)
		return 2
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

func writeJSON(
	output, errorOutput io.Writer,
	domain string,
	recordType dns.RecordType,
	records []string,
) int {
	result := struct {
		Domain  string         `json:"domain"`
		Type    dns.RecordType `json:"type"`
		Records []string       `json:"records"`
	}{
		Domain:  domain,
		Type:    recordType,
		Records: records,
	}

	if err := json.NewEncoder(output).Encode(result); err != nil {
		_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
		return 1
	}

	return 0
}
