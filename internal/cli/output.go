package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

// writeOutput writes DNS results as text or JSON.
func writeOutput(
	output, errorOutput io.Writer,
	opts cliOptions,
	records []string,
) int {
	if opts.jsonOutput {
		result := struct {
			Domain  string         `json:"domain"`
			Type    dns.RecordType `json:"type"`
			Records []string       `json:"records"`
		}{
			Domain:  opts.domain,
			Type:    opts.recordType,
			Records: records,
		}

		if err := json.NewEncoder(output).Encode(result); err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
			return 1
		}

		return 0
	}

	for _, record := range records {
		var err error

		if opts.recordType == dns.RecordTypeTXT ||
			opts.recordType == dns.RecordTypeCNAME ||
			opts.recordType == dns.RecordTypePTR {
			_, err = fmt.Fprintf(output, "%q\n", record)
		} else {
			_, err = fmt.Fprintln(output, record)
		}

		if err != nil {
			_, _ = fmt.Fprintf(errorOutput, "Output failed: %v\n", err)
			return 1
		}
	}

	return 0
}
