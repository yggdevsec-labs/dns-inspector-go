package cli

import (
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
		return writeJSON(
			output,
			errorOutput,
			opts.domain,
			opts.recordType,
			records,
		)
	}

	for _, record := range records {
		var err error

		if opts.recordType == dns.RecordTypeTXT ||
			opts.recordType == dns.RecordTypeCNAME {
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
