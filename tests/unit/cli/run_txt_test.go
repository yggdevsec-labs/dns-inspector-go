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

type mockCLITXTResolver struct {
	lookup func(context.Context, string) ([]string, error)
}

func (m mockCLITXTResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLITXTResolver) LookupTXT(
	ctx context.Context, domain string,
) ([]string, error) {
	return m.lookup(ctx, domain)
}

func TestRunTXT(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		records    []string
		lookupErr  error
		wantOutput string
		wantError  string
		wantCode   int
		failOutput bool
	}{
		{
			name:       "uppercase",
			recordType: "TXT",
			records:    []string{"v=spf1 -all", "verification=abc"},
			wantOutput: "\"v=spf1 -all\"\n\"verification=abc\"\n",
		},
		{
			name:       "lowercase",
			recordType: "txt",
			records:    []string{"v=spf1 -all"},
			wantOutput: "\"v=spf1 -all\"\n",
		},
		{
			name:       "no records",
			recordType: "TXT",
			wantError:  "No TXT records found\n",
			wantCode:   1,
		},
		{
			name:       "resolver error",
			recordType: "TXT",
			lookupErr:  errors.New("DNS timeout"),
			wantError:  "DNS lookup failed: DNS timeout\n",
			wantCode:   1,
		},
		{
			name:       "output failure",
			recordType: "TXT",
			records:    []string{"v=spf1 -all"},
			wantError:  "Output failed: write failed\n",
			wantCode:   1,
			failOutput: true,
		},
		{
			name:       "escape terminal control characters",
			recordType: "TXT",
			records:    []string{"safe\x1b[31mred\nsecond line"},
			wantOutput: "\"safe\\x1b[31mred\\nsecond line\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLITXTResolver{
				lookup: func(ctx context.Context, domain string) ([]string, error) {
					if domain != "example.com" {
						t.Errorf("unexpected domain: %q", domain)
					}
					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return tt.records, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", tt.recordType, "example.com"},
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

func TestRunTXTUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "TXT", "example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support TXT lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}
