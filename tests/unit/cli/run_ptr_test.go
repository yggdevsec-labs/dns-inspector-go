package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
)

type mockCLIPTRResolver struct {
	lookup func(context.Context, string) ([]string, error)
}

func (m mockCLIPTRResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLIPTRResolver) LookupAddr(
	ctx context.Context,
	addr string,
) ([]string, error) {
	return m.lookup(ctx, addr)
}

func TestRunPTR(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		ip         string
		records    []string
		wantOutput string
	}{
		{
			name:       "IPv4",
			args:       []string{"--type", "PTR", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"dns.google."},
			wantOutput: "\"dns.google.\"\n",
		},
		{
			name:       "IPv6",
			args:       []string{"--type", "PTR", "2001:4860:4860::8888"},
			ip:         "2001:4860:4860::8888",
			records:    []string{"dns.google."},
			wantOutput: "\"dns.google.\"\n",
		},
		{
			name:       "lowercase",
			args:       []string{"--type", "ptr", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"dns.google."},
			wantOutput: "\"dns.google.\"\n",
		},
		{
			name:       "multiple hostnames",
			args:       []string{"--type", "PTR", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"host1.example.com.", "host2.example.com."},
			wantOutput: "\"host1.example.com.\"\n\"host2.example.com.\"\n",
		},
		{
			name:       "escape terminal control characters",
			args:       []string{"--type", "PTR", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"host\x1b[31m.example.com."},
			wantOutput: "\"host\\x1b[31m.example.com.\"\n",
		},
		{
			name:       "JSON",
			args:       []string{"--type", "PTR", "--json", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"dns.google."},
			wantOutput: "{\"domain\":\"8.8.8.8\",\"type\":\"PTR\",\"records\":[\"dns.google.\"]}\n",
		},
		{
			name:       "JSON reversed flags",
			args:       []string{"--json", "--type", "ptr", "8.8.8.8"},
			ip:         "8.8.8.8",
			records:    []string{"dns.google."},
			wantOutput: "{\"domain\":\"8.8.8.8\",\"type\":\"PTR\",\"records\":[\"dns.google.\"]}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLIPTRResolver{
				lookup: func(ctx context.Context, addr string) ([]string, error) {
					if addr != tt.ip {
						t.Errorf("expected IP %q, got %q", tt.ip, addr)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return tt.records, nil
				},
			}

			code := cli.Run(tt.args, &output, &errorOutput, resolver)

			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}

			if output.String() != tt.wantOutput {
				t.Errorf("expected %q, got %q",
					tt.wantOutput, output.String())
			}

			if errorOutput.Len() != 0 {
				t.Errorf("unexpected error: %q", errorOutput.String())
			}
		})
	}
}

func TestRunPTRErrors(t *testing.T) {
	tests := []struct {
		name       string
		records    []string
		lookupErr  error
		failOutput bool
		wantError  string
	}{
		{
			name:      "no records",
			wantError: "No PTR records found\n",
		},
		{
			name:      "DNS failure",
			lookupErr: errors.New("DNS timeout"),
			wantError: "DNS lookup failed: DNS timeout\n",
		},
		{
			name:       "output failure",
			records:    []string{"dns.google."},
			failOutput: true,
			wantError:  "Output failed: write failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLIPTRResolver{
				lookup: func(context.Context, string) ([]string, error) {
					return tt.records, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", "PTR", "8.8.8.8"},
				writer,
				&errorOutput,
				resolver,
			)

			if code != 1 {
				t.Errorf("expected exit code 1, got %d", code)
			}

			if errorOutput.String() != tt.wantError {
				t.Errorf("expected %q, got %q",
					tt.wantError, errorOutput.String())
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}
		})
	}
}

func TestRunPTRInvalidIP(t *testing.T) {
	addresses := []string{
		"example.com",
		"999.999.999.999",
		"8.8.8.8\n",
		"8.8.8.8\x1b[31m",
		" 8.8.8.8",
	}

	for _, addr := range addresses {
		t.Run(addr, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLIPTRResolver{
				lookup: func(context.Context, string) ([]string, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(
				[]string{"--type", "PTR", addr},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}

			if !strings.Contains(errorOutput.String(), "Invalid IP address") {
				t.Errorf("unexpected error: %q", errorOutput.String())
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}
		})
	}
}

func TestRunPTRUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("IP resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "PTR", "8.8.8.8"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support PTR lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}
