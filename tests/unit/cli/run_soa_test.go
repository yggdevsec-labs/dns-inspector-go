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

type mockCLISOAResolver struct {
	lookup func(context.Context, string) (*dns.SOARecord, error)
}

func (m mockCLISOAResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLISOAResolver) LookupSOA(
	ctx context.Context,
	domain string,
) (*dns.SOARecord, error) {
	return m.lookup(ctx, domain)
}

func TestRunSOA(t *testing.T) {
	const textRecord = "\"ns1.example.com.\" \"hostmaster.example.com.\" 2026111201 7200 3600 1209600 3600"

	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{
			name:       "uppercase",
			args:       []string{"--type", "SOA", "example.com"},
			wantOutput: textRecord + "\n",
		},
		{
			name:       "lowercase",
			args:       []string{"--type", "soa", "example.com"},
			wantOutput: textRecord + "\n",
		},
		{
			name:       "JSON",
			args:       []string{"--type", "SOA", "--json", "example.com"},
			wantOutput: `{"domain":"example.com","type":"SOA","records":["\"ns1.example.com.\" \"hostmaster.example.com.\" 2026111201 7200 3600 1209600 3600"]}` + "\n",
		},
		{
			name:       "JSON reversed flags",
			args:       []string{"--json", "--type", "soa", "example.com"},
			wantOutput: `{"domain":"example.com","type":"SOA","records":["\"ns1.example.com.\" \"hostmaster.example.com.\" 2026111201 7200 3600 1209600 3600"]}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLISOAResolver{
				lookup: func(
					ctx context.Context,
					domain string,
				) (*dns.SOARecord, error) {
					if domain != "example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return &dns.SOARecord{
						NS:      "ns1.example.com.",
						MBox:    "hostmaster.example.com.",
						Serial:  2026111201,
						Refresh: 7200,
						Retry:   3600,
						Expire:  1209600,
						MinTTL:  3600,
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

func TestRunSOAErrors(t *testing.T) {
	tests := []struct {
		name       string
		record     *dns.SOARecord
		lookupErr  error
		failOutput bool
		wantError  string
	}{
		{
			name:      "no SOA record",
			wantError: "No SOA records found\n",
		},
		{
			name:      "DNS failure",
			lookupErr: errors.New("DNS timeout"),
			wantError: "DNS lookup failed: DNS timeout\n",
		},
		{
			name: "output failure",
			record: &dns.SOARecord{
				NS:   "ns1.example.com.",
				MBox: "hostmaster.example.com.",
			},
			failOutput: true,
			wantError:  "Output failed: write failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLISOAResolver{
				lookup: func(
					context.Context,
					string,
				) (*dns.SOARecord, error) {
					return tt.record, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", "SOA", "example.com"},
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

func TestRunSOAInvalidDomain(t *testing.T) {
	domains := []string{
		"bad..example.com",
		"example.com\n",
		"example.com\x1b[31m",
	}

	for _, domain := range domains {
		t.Run(domain, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLISOAResolver{
				lookup: func(
					context.Context,
					string,
				) (*dns.SOARecord, error) {
					t.Fatal("resolver must not be called")
					return nil, nil
				},
			}

			code := cli.Run(
				[]string{"--type", "SOA", domain},
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

func TestRunSOAUnsupportedResolver(t *testing.T) {
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
		[]string{"--type", "SOA", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support SOA lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q",
			expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}

func TestRunSOAEscapesControlCharacters(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockCLISOAResolver{
		lookup: func(
			context.Context, string,
		) (*dns.SOARecord, error) {
			return &dns.SOARecord{
				NS:   "ns1\x1b[31m.example.com.",
				MBox: "hostmaster.example.com.",
			}, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "SOA", "example.com"},
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
