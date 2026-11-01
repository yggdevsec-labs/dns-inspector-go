package cli_test

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
)

func TestRunInvalidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{
			name:   "empty label",
			domain: "example..com",
		},
		{
			name:   "leading hyphen",
			domain: "-example.com",
		},
		{
			name:   "trailing hyphen",
			domain: "example-.com",
		},
		{
			name:   "invalid character",
			domain: "example!.com",
		},
		{
			name:   "newline",
			domain: "example.com\n",
		},
		{
			name:   "ANSI escape sequence",
			domain: "evil\x1b[31m.com",
		},
		{
			name:   "label too long",
			domain: strings.Repeat("a", 64) + ".com",
		},
		{
			name:   "domain too long",
			domain: strings.Repeat("a.", 126) + "aa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockResolver{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					t.Fatal("DNS resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(
				[]string{"--type", "A", tt.domain},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}

			if !strings.HasPrefix(
				errorOutput.String(),
				"Invalid domain: ",
			) {
				t.Errorf(
					"unexpected error message: %q",
					errorOutput.String(),
				)
			}
		})
	}
}

func TestRunValidDomain(t *testing.T) {
	domains := []string{
		"example.com",
		"_dmarc.example.com",
		"example.com.",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockResolver{
				lookup: func(
					_ context.Context,
					network, host string,
				) ([]net.IP, error) {
					if network != "ip4" {
						t.Errorf("unexpected network: %q", network)
					}
					if host != domain {
						t.Errorf("unexpected domain: %q", host)
					}

					return []net.IP{net.ParseIP("192.0.2.1")}, nil
				},
			}

			code := cli.Run(
				[]string{domain},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}

			if output.String() != "192.0.2.1\n" {
				t.Errorf("unexpected output: %q", output.String())
			}

			if errorOutput.Len() != 0 {
				t.Errorf(
					"unexpected error: %q",
					errorOutput.String(),
				)
			}
		})
	}
}
