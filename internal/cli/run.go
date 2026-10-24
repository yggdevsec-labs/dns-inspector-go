package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

const lookupTimeout = 5 * time.Second

// Run executes an A-record lookup and returns an exit code.
func Run(args []string, output, errorOutput io.Writer, resolver dns.IPResolver) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(errorOutput, "Usage: dns-inspector <domain>")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	addresses, err := dns.LookupA(ctx, resolver, args[0])
	if err != nil {
		fmt.Fprintf(errorOutput, "DNS lookup failed: %v\n", err)
		return 1
	}

	if len(addresses) == 0 {
		fmt.Fprintln(errorOutput, "No A records found")
		return 1
	}

	for _, address := range addresses {
		fmt.Fprintln(output, address)
	}

	return 0
}
