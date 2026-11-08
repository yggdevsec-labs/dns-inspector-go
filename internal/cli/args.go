package cli

import (
	"strings"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

// cliOptions holds parsed command-line arguments.
type cliOptions struct {
	recordType dns.RecordType
	domain     string
	jsonOutput bool
}

// parseArgs parses the supported command-line argument combinations.
func parseArgs(args []string) (cliOptions, bool) {
	opts := cliOptions{
		recordType: dns.RecordTypeA,
	}

	switch {
	case len(args) == 1:
		opts.domain = args[0]

	case len(args) == 2 && args[0] == "--json":
		opts.jsonOutput = true
		opts.domain = args[1]

	case len(args) == 3 && args[0] == "--type":
		opts.recordType = dns.RecordType(strings.ToUpper(args[1]))
		opts.domain = args[2]

	case len(args) == 4 && args[0] == "--type" && args[2] == "--json":
		opts.recordType = dns.RecordType(strings.ToUpper(args[1]))
		opts.jsonOutput = true
		opts.domain = args[3]

	case len(args) == 4 && args[0] == "--json" && args[1] == "--type":
		opts.recordType = dns.RecordType(strings.ToUpper(args[2]))
		opts.jsonOutput = true
		opts.domain = args[3]

	default:
		return cliOptions{}, false
	}

	return opts, true
}
