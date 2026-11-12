package main

import (
	"os"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

func main() {
	os.Exit(cli.Run(
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		dns.NewDNSResolver(),
	))
}
