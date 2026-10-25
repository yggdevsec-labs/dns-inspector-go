package cli_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
)

type mockResolver struct {
	lookup func(context.Context, string, string) ([]net.IP, error)
}

func (m mockResolver) LookupIP(
	ctx context.Context,
	network, host string,
) ([]net.IP, error) {
	return m.lookup(ctx, network, host)
}

func TestRunSuccess(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
			if network != "ip4" {
				t.Errorf("expected network ip4, got %q", network)
			}
			if host != "example.com" {
				t.Errorf("unexpected domain: %q", host)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Error("expected DNS lookup timeout")
			}

			return []net.IP{
				net.ParseIP("192.0.2.1"),
				net.ParseIP("198.51.100.2"),
			}, nil
		},
	}

	code := cli.Run(
		[]string{"example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	expected := "192.0.2.1\n198.51.100.2\n"
	if output.String() != expected {
		t.Errorf("expected %q, got %q", expected, output.String())
	}

	if errorOutput.Len() != 0 {
		t.Errorf("unexpected error output: %q", errorOutput.String())
	}
}

func TestRunInvalidArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing domain"},
		{name: "empty domain", args: []string{""}},
		{name: "whitespace domain", args: []string{" \t "}},
		{name: "too many arguments", args: []string{"example.com", "other.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockResolver{
				lookup: func(context.Context, string, string) ([]net.IP, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(tt.args, &output, &errorOutput, resolver)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}

			if output.Len() != 0 {
				t.Errorf("unexpected standard output: %q", output.String())
			}

			expected := "Usage: dns-inspector <domain>\n"
			if errorOutput.String() != expected {
				t.Errorf("expected %q, got %q", expected, errorOutput.String())
			}
		})
	}
}

func TestRunDNSFailure(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("DNS timeout")
		},
	}

	code := cli.Run(
		[]string{"example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if output.Len() != 0 {
		t.Errorf("unexpected standard output: %q", output.String())
	}

	expected := "DNS lookup failed: DNS timeout\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}

func TestRunNoRecords(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	if output.Len() != 0 {
		t.Errorf("unexpected standard output: %q", output.String())
	}

	expected := "No A records found\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunOutputFailure(t *testing.T) {
	var errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}

	code := cli.Run(
		[]string{"example.com"},
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
