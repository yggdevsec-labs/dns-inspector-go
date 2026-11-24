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
	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

type mockCLICAAResolver struct {
	lookup func(context.Context, string) ([]dns.CAARecord, error)
}

func (m mockCLICAAResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLICAAResolver) LookupCAA(
	ctx context.Context,
	domain string,
) ([]dns.CAARecord, error) {
	return m.lookup(ctx, domain)
}

func TestRunCAA(t *testing.T) {
	const textOutput = "0 \"issue\" \"letsencrypt.org\"\n" +
		"128 \"iodef\" \"mailto:security@example.com\"\n"

	const jsonOutput = `{"domain":"example.com","type":"CAA",` +
		`"records":["0 \"issue\" \"letsencrypt.org\"",` +
		`"128 \"iodef\" \"mailto:security@example.com\""]}` + "\n"

	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{
			name:       "uppercase",
			args:       []string{"--type", "CAA", "example.com"},
			wantOutput: textOutput,
		},
		{
			name:       "lowercase",
			args:       []string{"--type", "caa", "example.com"},
			wantOutput: textOutput,
		},
		{
			name:       "JSON",
			args:       []string{"--type", "CAA", "--json", "example.com"},
			wantOutput: jsonOutput,
		},
		{
			name:       "JSON reversed flags",
			args:       []string{"--json", "--type", "caa", "example.com"},
			wantOutput: jsonOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLICAAResolver{
				lookup: func(
					ctx context.Context,
					domain string,
				) ([]dns.CAARecord, error) {
					if domain != "example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return []dns.CAARecord{
						{
							Flag:  0,
							Tag:   "issue",
							Value: "letsencrypt.org",
						},
						{
							Flag:  128,
							Tag:   "iodef",
							Value: "mailto:security@example.com",
						},
					}, nil
				},
			}

			code := cli.Run(
				tt.args,
				&output,
				&errorOutput,
				resolver,
			)

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

func TestRunCAAErrors(t *testing.T) {
	tests := []struct {
		name       string
		records    []dns.CAARecord
		lookupErr  error
		failOutput bool
		wantError  string
	}{
		{
			name:      "no records",
			wantError: "No CAA records found\n",
		},
		{
			name:      "DNS failure",
			lookupErr: errors.New("DNS timeout"),
			wantError: "DNS lookup failed: DNS timeout\n",
		},
		{
			name: "output failure",
			records: []dns.CAARecord{
				{Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			},
			failOutput: true,
			wantError:  "Output failed: write failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLICAAResolver{
				lookup: func(
					context.Context,
					string,
				) ([]dns.CAARecord, error) {
					return tt.records, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", "CAA", "example.com"},
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

func TestRunCAAInvalidDomain(t *testing.T) {
	domains := []string{
		"bad..example.com",
		"example.com\n",
		"example.com\x1b[31m",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLICAAResolver{
				lookup: func(
					context.Context,
					string,
				) ([]dns.CAARecord, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(
				[]string{"--type", "CAA", domain},
				&output,
				&errorOutput,
				resolver,
			)

			if code != 2 {
				t.Errorf("expected exit code 2, got %d", code)
			}

			if !strings.Contains(
				errorOutput.String(), "Invalid domain:",
			) {
				t.Errorf("unexpected error: %q",
					errorOutput.String())
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}
		})
	}
}

func TestRunCAAUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(
			context.Context, string, string,
		) ([]net.IP, error) {
			t.Fatal("IP resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "CAA", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support CAA lookups\n"

	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q",
			expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunCAAEscapesControlCharacters(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockCLICAAResolver{
		lookup: func(
			context.Context,
			string,
		) ([]dns.CAARecord, error) {
			return []dns.CAARecord{
				{
					Flag:  0,
					Tag:   "issue",
					Value: "example\x1b[31m.com",
				},
			}, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "CAA", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: %s",
			code, errorOutput.String())
	}

	if strings.Contains(output.String(), "\x1b") {
		t.Error("output contains an unescaped terminal control character")
	}

	if !strings.Contains(output.String(), `\x1b`) {
		t.Errorf("expected escaped control character, got %q",
			output.String())
	}
}
