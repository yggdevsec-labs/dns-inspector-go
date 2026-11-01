package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
)

type mockCLICNAMEResolver struct {
	lookup func(context.Context, string) (string, error)
}

func (m mockCLICNAMEResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLICNAMEResolver) LookupCNAME(
	ctx context.Context, domain string,
) (string, error) {
	return m.lookup(ctx, domain)
}

func TestRunCNAME(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		cname      string
		lookupErr  error
		wantOutput string
		wantError  string
		wantCode   int
		failOutput bool
	}{
		{
			name:       "uppercase",
			recordType: "CNAME",
			cname:      "target.example.com.",
			wantOutput: "\"target.example.com.\"\n",
		},
		{
			name:       "lowercase",
			recordType: "cname",
			cname:      "target.example.com.",
			wantOutput: "\"target.example.com.\"\n",
		},
		{
			name:       "no alias",
			recordType: "CNAME",
			cname:      "alias.example.com.",
			wantError:  "No CNAME alias found\n",
			wantCode:   1,
		},
		{
			name:       "no alias case insensitive",
			recordType: "CNAME",
			cname:      "ALIAS.EXAMPLE.COM.",
			wantError:  "No CNAME alias found\n",
			wantCode:   1,
		},
		{
			name:       "resolver error",
			recordType: "CNAME",
			lookupErr:  errors.New("DNS timeout"),
			wantError:  "DNS lookup failed: DNS timeout\n",
			wantCode:   1,
		},
		{
			name:       "output failure",
			recordType: "CNAME",
			cname:      "target.example.com.",
			wantError:  "Output failed: write failed\n",
			wantCode:   1,
			failOutput: true,
		},
		{
			name:       "escape terminal control characters",
			recordType: "CNAME",
			cname:      "target\x1b[31m.example.com.",
			wantOutput: "\"target\\x1b[31m.example.com.\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLICNAMEResolver{
				lookup: func(ctx context.Context, domain string) (string, error) {
					if domain != "alias.example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return tt.cname, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", tt.recordType, "alias.example.com"},
				writer,
				&errorOutput,
				resolver,
			)

			if code != tt.wantCode {
				t.Errorf("expected exit code %d, got %d", tt.wantCode, code)
			}

			if output.String() != tt.wantOutput {
				t.Errorf("expected output %q, got %q", tt.wantOutput, output.String())
			}

			if errorOutput.String() != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, errorOutput.String())
			}
		})
	}
}

func TestRunCNAMEUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "CNAME", "alias.example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support CNAME lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}
