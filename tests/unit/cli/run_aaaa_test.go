package cli_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

func TestRunAAAA(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
	}{
		{name: "uppercase", recordType: string(dns.RecordTypeAAAA)},
		{name: "lowercase", recordType: "aaaa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockResolver{
				lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
					if network != "ip6" {
						t.Errorf("expected ip6, got %q", network)
					}
					if host != "example.com" {
						t.Errorf("unexpected domain: %q", host)
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected lookup timeout")
					}

					return []net.IP{
						net.ParseIP("2001:db8::1"),
					}, nil
				},
			}

			code := cli.Run(
				[]string{"--type", tt.recordType, "example.com"},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}

			expected := "2001:db8::1\n"
			if output.String() != expected {
				t.Errorf("expected %q, got %q", expected, output.String())
			}

			if errorOutput.Len() != 0 {
				t.Errorf("unexpected error output: %q", errorOutput.String())
			}
		})
	}
}

func TestRunAAAANoRecords(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", string(dns.RecordTypeAAAA), "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "No AAAA records found\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunAAAAResolverError(t *testing.T) {
	var output, errorOutput bytes.Buffer

	expectedErr := errors.New("DNS timeout")

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, expectedErr
		},
	}

	code := cli.Run(
		[]string{"--type", string(dns.RecordTypeAAAA), "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: DNS timeout\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunUnsupportedRecordType(t *testing.T) {
	recordTypes := []string{
		string(dns.RecordTypeMX),
		string(dns.RecordTypeTXT),
		"INVALID",
	}

	for _, recordType := range recordTypes {
		t.Run(recordType, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockResolver{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(
				[]string{"--type", recordType, "example.com"},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}

			expected := "Unsupported record type: use A or AAAA\n"
			if errorOutput.String() != expected {
				t.Errorf("expected %q, got %q", expected, errorOutput.String())
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}
		})
	}
}
