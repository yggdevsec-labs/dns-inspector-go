package main

import (
	"net"
	"os"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		net.DefaultResolver,
	))
}
