package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

// lookupRecords resolves DNS records without formatting output.
func lookupRecords(
	ctx context.Context,
	resolver dns.IPResolver,
	recordType dns.RecordType,
	domain string,
) ([]string, error) {
	switch recordType {
	case dns.RecordTypeA, dns.RecordTypeAAAA:
		var addresses []net.IP
		var err error

		if recordType == dns.RecordTypeAAAA {
			addresses, err = dns.LookupAAAA(ctx, resolver, domain)
		} else {
			addresses, err = dns.LookupA(ctx, resolver, domain)
		}

		if err != nil {
			return nil, err
		}

		records := make([]string, 0, len(addresses))
		for _, address := range addresses {
			records = append(records, address.String())
		}
		return records, nil

	case dns.RecordTypeMX:
		mxResolver, ok := resolver.(dns.MXResolver)
		if !ok {
			return nil, errors.New("resolver does not support MX lookups")
		}

		mxRecords, err := dns.LookupMX(ctx, mxResolver, domain)
		if err != nil {
			return nil, err
		}

		records := make([]string, 0, len(mxRecords))
		for _, record := range mxRecords {
			records = append(records,
				fmt.Sprintf("%d %s", record.Pref, record.Host))
		}
		return records, nil

	case dns.RecordTypeNS:
		nsResolver, ok := resolver.(dns.NSResolver)
		if !ok {
			return nil, errors.New("resolver does not support NS lookups")
		}

		nsRecords, err := dns.LookupNS(ctx, nsResolver, domain)
		if err != nil {
			return nil, err
		}

		records := make([]string, 0, len(nsRecords))
		for _, record := range nsRecords {
			records = append(records, record.Host)
		}
		return records, nil

	case dns.RecordTypeTXT:
		txtResolver, ok := resolver.(dns.TXTResolver)
		if !ok {
			return nil, errors.New("resolver does not support TXT lookups")
		}

		return dns.LookupTXT(ctx, txtResolver, domain)

	case dns.RecordTypeCNAME:
		cnameResolver, ok := resolver.(dns.CNAMEResolver)
		if !ok {
			return nil, errors.New("resolver does not support CNAME lookups")
		}

		cname, err := dns.LookupCNAME(ctx, cnameResolver, domain)
		if err != nil {
			return nil, err
		}

		if strings.EqualFold(
			strings.TrimSuffix(cname, "."),
			strings.TrimSuffix(domain, "."),
		) {
			return nil, nil
		}

		return []string{cname}, nil

	case dns.RecordTypeSRV:
		srvResolver, ok := resolver.(dns.SRVResolver)
		if !ok {
			return nil, errors.New("resolver does not support SRV lookups")
		}

		srvRecords, err := dns.LookupSRV(ctx, srvResolver, domain)
		if err != nil {
			return nil, err
		}

		records := make([]string, 0, len(srvRecords))
		for _, record := range srvRecords {
			records = append(records, fmt.Sprintf(
				"%d %d %d %s",
				record.Priority,
				record.Weight,
				record.Port,
				record.Target,
			))
		}

		return records, nil

	
	case dns.RecordTypePTR:
		ptrResolver, ok := resolver.(dns.PTRResolver)
		if !ok {
			return nil, errors.New("resolver does not support PTR lookups")
		}

		return dns.LookupPTR(ctx, ptrResolver, domain)


	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}
}
