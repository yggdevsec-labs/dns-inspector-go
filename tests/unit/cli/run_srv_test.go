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

type mockCLISRVResolver struct {
	lookup func(context.Context, string, string, string) (string, []*net.SRV, error)
}

func (m mockCLISRVResolver) LookupIP(
	context.Context, string, string,
) ([]net.IP, error) {
	return nil, errors.New("unexpected IP lookup")
}

func (m mockCLISRVResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	return m.lookup(ctx, service, proto, name)
}

func TestRunSRV(t *testing.T) {
	const domain = "_sip._tcp.example.com"

	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{
			name: "uppercase",
			args: []string{"--type", "SRV", domain},
			wantOutput: "10 60 5060 sip1.example.com.\n" +
				"20 40 5060 sip2.example.com.\n",
		},
		{
			name: "lowercase",
			args: []string{"--type", "srv", domain},
			wantOutput: "10 60 5060 sip1.example.com.\n" +
				"20 40 5060 sip2.example.com.\n",
		},
		{
			name: "JSON",
			args: []string{"--type", "SRV", "--json", domain},
			wantOutput: `{"domain":"_sip._tcp.example.com","type":"SRV",` +
				`"records":["10 60 5060 sip1.example.com.",` +
				`"20 40 5060 sip2.example.com."]}` + "\n",
		},
		{
			name: "JSON reversed flags",
			args: []string{"--json", "--type", "srv", domain},
			wantOutput: `{"domain":"_sip._tcp.example.com","type":"SRV",` +
				`"records":["10 60 5060 sip1.example.com.",` +
				`"20 40 5060 sip2.example.com."]}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLISRVResolver{
				lookup: func(
					ctx context.Context,
					service, proto, name string,
				) (string, []*net.SRV, error) {
					if service != "" || proto != "" {
						t.Errorf("unexpected service or proto: %q, %q",
							service, proto)
					}

					if name != domain {
						t.Errorf("unexpected domain: %q", name)
					}

					if _, ok := ctx.Deadline(); !ok {
						t.Error("expected DNS lookup timeout")
					}

					return "", []*net.SRV{
						{
							Target:   "sip1.example.com.",
							Port:     5060,
							Priority: 10,
							Weight:   60,
						},
						{
							Target:   "sip2.example.com.",
							Port:     5060,
							Priority: 20,
							Weight:   40,
						},
					}, nil
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

func TestRunSRVErrors(t *testing.T) {
	tests := []struct {
		name       string
		records    []*net.SRV
		lookupErr  error
		failOutput bool
		wantError  string
	}{
		{
			name:      "no records",
			wantError: "No SRV records found\n",
		},
		{
			name:      "DNS failure",
			lookupErr: errors.New("DNS timeout"),
			wantError: "DNS lookup failed: DNS timeout\n",
		},
		{
			name: "output failure",
			records: []*net.SRV{
				{Target: "sip.example.com.", Port: 5060},
			},
			failOutput: true,
			wantError:  "Output failed: write failed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			resolver := mockCLISRVResolver{
				lookup: func(
					context.Context, string, string, string,
				) (string, []*net.SRV, error) {
					return "", tt.records, tt.lookupErr
				},
			}

			var writer io.Writer = &output
			if tt.failOutput {
				writer = failingWriter{}
			}

			code := cli.Run(
				[]string{"--type", "SRV", "_sip._tcp.example.com"},
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

func TestRunSRVUnsupportedResolver(t *testing.T) {
	var output, errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			t.Fatal("IP resolver must not be called")
			return nil, nil
		},
	}

	code := cli.Run(
		[]string{"--type", "SRV", "_sip._tcp.example.com"},
		&output,
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "DNS lookup failed: resolver does not support SRV lookups\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q", expected, errorOutput.String())
	}

	if output.Len() != 0 {
		t.Errorf("unexpected output: %q", output.String())
	}
}
