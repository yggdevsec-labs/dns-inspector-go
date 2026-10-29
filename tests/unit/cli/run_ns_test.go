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

type mockCLINSResolver struct {
	lookup func(context.Context, string) ([]*net.NS, error)
}

func (m mockCLINSResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLINSResolver) LookupNS(
	ctx context.Context, domain string,
) ([]*net.NS, error) {
	return m.lookup(ctx, domain)
}

func TestRunNSSuccess(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
	}{
		{"uppercase", string(dns.RecordTypeNS)},
		{"lowercase", "ns"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLINSResolver{
				lookup: func(ctx context.Context, domain string) ([]*net.NS, error) {
					if domain != "example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return []*net.NS{
						{Host: "ns1.example.com."},
						{Host: "ns2.example.com."},
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

			expected := "ns1.example.com.\nns2.example.com.\n"
			if output.String() != expected {
				t.Errorf("expected %q, got %q", expected, output.String())
			}

			if errorOutput.Len() != 0 {
				t.Errorf("unexpected error output: %q", errorOutput.String())
			}
		})
	}
}

func TestRunNSNoRecords(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockCLINSResolver{
		lookup: func(context.Context, string) ([]*net.NS, error) {
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "NS", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}

	expected := "No NS records found\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}

func TestRunNSResolverError(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockCLINSResolver{
		lookup: func(context.Context, string) ([]*net.NS, error) {
			return nil, errors.New("DNS timeout")
		},
	}

	code := cli.Run(
		[]string{"--type", "NS", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}

	expected := "DNS lookup failed: DNS timeout\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}

func TestRunNSUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "NS", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support NS lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunNSOutputFailure(t *testing.T) {
	var errorOutput bytes.Buffer

	resolver := mockCLINSResolver{
		lookup: func(context.Context, string) ([]*net.NS, error) {
			return []*net.NS{
				{Host: "ns1.example.com."},
			}, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "NS", "example.com"},
		failingWriter{},
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "Output failed: write failed\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}
