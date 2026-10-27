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

type mockCLIMXResolver struct {
	lookup func(context.Context, string) ([]*net.MX, error)
}

func (m mockCLIMXResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLIMXResolver) LookupMX(
	ctx context.Context, domain string,
) ([]*net.MX, error) {
	return m.lookup(ctx, domain)
}

func TestRunMXSuccess(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
	}{
		{"uppercase", string(dns.RecordTypeMX)},
		{"lowercase", "mx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLIMXResolver{
				lookup: func(ctx context.Context, domain string) ([]*net.MX, error) {
					if domain != "example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return []*net.MX{
						{Host: "mail.example.com.", Pref: 10},
						{Host: "backup.example.com.", Pref: 20},
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

			expected := "10 mail.example.com.\n20 backup.example.com.\n"
			if output.String() != expected {
				t.Errorf("expected %q, got %q", expected, output.String())
			}

			if errorOutput.Len() != 0 {
				t.Errorf("unexpected error output: %q", errorOutput.String())
			}
		})
	}
}

func TestRunMXNoRecords(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockCLIMXResolver{
		lookup: func(context.Context, string) ([]*net.MX, error) {
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "MX", "example.com"},
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

	expected := "No MX records found\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}

func TestRunMXResolverError(t *testing.T) {
	var output, errorOutput bytes.Buffer

	expectedErr := errors.New("DNS timeout")

	resolver := mockCLIMXResolver{
		lookup: func(context.Context, string) ([]*net.MX, error) {
			return nil, expectedErr
		},
	}

	code := cli.Run(
		[]string{"--type", "MX", "example.com"},
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

func TestRunMXUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "MX", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support MX lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunMXOutputFailure(t *testing.T) {
	var errorOutput bytes.Buffer

	resolver := mockCLIMXResolver{
		lookup: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{
				{Host: "mail.example.com.", Pref: 10},
			}, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "MX", "example.com"},
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
