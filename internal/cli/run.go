package cli

import (
	"context"
	"encoding/json"
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
	recordType := dns.RecordTypeA
	jsonOutput := false
	var domain string

	switch {
	case len(args) == 1:
		domain = args[0]
	case len(args) == 2 && args[0] == "--json":
		jsonOutput = true
		domain = args[1]
	case len(args) == 3 && args[0] == "--type":
		recordType = dns.RecordType(strings.ToUpper(args[1]))
		domain = args[2]
	case len(args) == 4 && args[0] == "--type" && args[2] == "--json":
		recordType = dns.RecordType(strings.ToUpper(args[1]))
		jsonOutput = true
		domain = args[3]
	case len(args) == 4 && args[0] == "--json" && args[1] == "--type":
		recordType = dns.RecordType(strings.ToUpper(args[2]))
		jsonOutput = true
		domain = args[3]
	default:
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	if strings.TrimSpace(domain) == "" {
		_, _ = fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	switch recordType {
	case dns.RecordTypeA, dns.RecordTypeAAAA, dns.RecordTypeMX,
		dns.RecordTypeNS, dns.RecordTypeTXT, dns.RecordTypeCNAME:
	default:
		_, _ = fmt.Fprintln(errorOutput,
			"Unsupported record type: use A, AAAA, MX, NS, TXT or CNAME")
		return 2
	}

	if err := dns.ValidateDomain(domain); err != nil {
		_, _ = fmt.Fprintf(errorOutput, "Invalid domain: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	if recordType == dns.RecordTypeMX {
		mxResolver, ok := resolver.(dns.MXResolver)
		if !ok {
			_, _ = fmt.Fprintln(errorOutput, "DNS lookup failed: resolver does not support MX lookups")
			return 1
		}

		records, err := dns.LookupMX(ctx, mxResolver, domain)
		if err != nil {
			_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
			return 1
		}

		if len(records) == 0 {
			_, _ = fmt.Fprintln(errorOutput, "No MX records found")
			return 1
		}

		if jsonOutput {
			values := make([]string, 0, len(records))
			for _, record := range records {
				values = append(values, fmt.Sprintf("%d %s", record.Pref, record.Host))
			}
			return writeJSON(output, errorOutput, domain, recordType, values)
		}

		for _, record := range records {
			if _, err := fmt.Fprintf(output, "%d %s\n", record.Pref, record.Host); err != nil {
				_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
				return 1
			}
		}

		return 0
	}

	if recordType == dns.RecordTypeNS {
		nsResolver, ok := resolver.(dns.NSResolver)
		if !ok {
			_, _ = fmt.Fprintln(errorOutput, "DNS lookup failed: resolver does not support NS lookups")
			return 1
		}

		records, err := dns.LookupNS(ctx, nsResolver, domain)
		if err != nil {
			_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
			return 1
		}

		if len(records) == 0 {
			_, _ = fmt.Fprintln(errorOutput, "No NS records found")
			return 1
		}

		if jsonOutput {
			values := make([]string, 0, len(records))
			for _, record := range records {
				values = append(values, record.Host)
			}
			return writeJSON(output, errorOutput, domain, recordType, values)
		}

		for _, record := range records {
			if _, err := fmt.Fprintln(output, record.Host); err != nil {
				_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
				return 1
			}
		}

		return 0
	}

	if recordType == dns.RecordTypeTXT {
		txtResolver, ok := resolver.(dns.TXTResolver)
		if !ok {
			_, _ = fmt.Fprintln(errorOutput,
				"DNS lookup failed: resolver does not support TXT lookups")
			return 1
		}

		records, err := dns.LookupTXT(ctx, txtResolver, domain)
		if err != nil {
			_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
			return 1
		}

		if len(records) == 0 {
			_, _ = fmt.Fprintln(errorOutput, "No TXT records found")
			return 1
		}

		if jsonOutput {
			return writeJSON(output, errorOutput, domain, recordType, records)
		}

		for _, record := range records {
			if _, err := fmt.Fprintf(output, "%q\n", record); err != nil {
				_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
				return 1
			}
		}

		return 0
	}

	if recordType == dns.RecordTypeCNAME {
		cnameResolver, ok := resolver.(dns.CNAMEResolver)
		if !ok {
			_, _ = fmt.Fprintln(errorOutput,
				"DNS lookup failed: resolver does not support CNAME lookups")
			return 1
		}

		cname, err := dns.LookupCNAME(ctx, cnameResolver, domain)
		if err != nil {
			_, _ = fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
			return 1
		}

		if strings.EqualFold(
			strings.TrimSuffix(cname, "."),
			strings.TrimSuffix(domain, "."),
		) {
			_, _ = fmt.Fprintln(errorOutput, "No CNAME alias found")
			return 1
		}

		if jsonOutput {
			return writeJSON(output, errorOutput, domain, recordType, []string{cname})
		}

		if _, err := fmt.Fprintf(output, "%q\n", cname); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
			return 1
		}

		return 0
	}

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

	if jsonOutput {
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
		}
		return writeJSON(output, errorOutput, domain, recordType, values)
	}

	for _, address := range addresses {
		if _, err := fmt.Fprintln(output, address); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
			return 1
		}
	}

	return 0
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
