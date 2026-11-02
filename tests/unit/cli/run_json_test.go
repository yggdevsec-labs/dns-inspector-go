package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/cli"
	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

func TestRunJSON(t *testing.T) {
	ipResolver := mockResolver{
		lookup: func(_ context.Context, network, _ string) ([]net.IP, error) {
			if network == "ip6" {
				return []net.IP{net.ParseIP("2001:db8::1")}, nil
			}
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}

	tests := []struct {
		name        string
		args        []string
		resolver    dns.IPResolver
		wantType    string
		wantRecords []string
	}{
		{
			name:        "default A",
			args:        []string{"--json", "example.com"},
			resolver:    ipResolver,
			wantType:    "A",
			wantRecords: []string{"192.0.2.1"},
		},
		{
			name:        "AAAA with reversed flags",
			args:        []string{"--json", "--type", "AAAA", "example.com"},
			resolver:    ipResolver,
			wantType:    "AAAA",
			wantRecords: []string{"2001:db8::1"},
		},
		{
			name: "MX",
			args: []string{"--type", "MX", "--json", "example.com"},
			resolver: mockCLIMXResolver{
				lookup: func(context.Context, string) ([]*net.MX, error) {
					return []*net.MX{
						{Host: "mail.example.com.", Pref: 10},
					}, nil
				},
			},
			wantType:    "MX",
			wantRecords: []string{"10 mail.example.com."},
		},
		{
			name: "NS",
			args: []string{"--type", "NS", "--json", "example.com"},
			resolver: mockCLINSResolver{
				lookup: func(context.Context, string) ([]*net.NS, error) {
					return []*net.NS{
						{Host: "ns1.example.com."},
					}, nil
				},
			},
			wantType:    "NS",
			wantRecords: []string{"ns1.example.com."},
		},
		{
			name: "TXT with control characters",
			args: []string{"--type", "TXT", "--json", "example.com"},
			resolver: mockCLITXTResolver{
				lookup: func(context.Context, string) ([]string, error) {
					return []string{"value\x1b[31m\nnext"}, nil
				},
			},
			wantType:    "TXT",
			wantRecords: []string{"value\x1b[31m\nnext"},
		},
		{
			name: "CNAME",
			args: []string{"--type", "CNAME", "--json", "example.com"},
			resolver: mockCLICNAMEResolver{
				lookup: func(context.Context, string) (string, error) {
					return "target.example.com.", nil
				},
			},
			wantType:    "CNAME",
			wantRecords: []string{"target.example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			code := cli.Run(
				tt.args,
				&output,
				&errorOutput,
				tt.resolver,
			)

			if code != 0 {
				t.Fatalf("expected exit code 0, got %d: %s",
					code, errorOutput.String())
			}

			var result struct {
				Domain  string   `json:"domain"`
				Type    string   `json:"type"`
				Records []string `json:"records"`
			}

			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}

			if result.Domain != "example.com" {
				t.Errorf("unexpected domain: %q", result.Domain)
			}

			if result.Type != tt.wantType {
				t.Errorf("expected type %q, got %q",
					tt.wantType, result.Type)
			}

			if !reflect.DeepEqual(result.Records, tt.wantRecords) {
				t.Errorf("expected records %q, got %q",
					tt.wantRecords, result.Records)
			}

			if bytes.Contains(output.Bytes(), []byte{0x1b}) {
				t.Error("JSON contains an unescaped terminal control byte")
			}

			if errorOutput.Len() != 0 {
				t.Errorf("unexpected error: %q", errorOutput.String())
			}
		})
	}
}

func TestRunJSONErrors(t *testing.T) {
	noRecords := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, nil
		},
	}

	lookupError := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return nil, errors.New("DNS timeout")
		},
	}

	tests := []struct {
		name      string
		args      []string
		resolver  dns.IPResolver
		wantCode  int
		wantError string
	}{
		{
			name:      "invalid arguments",
			args:      []string{"--json", "--type", "A"},
			resolver:  noRecords,
			wantCode:  2,
			wantError: "Usage:",
		},
		{
			name:      "invalid domain",
			args:      []string{"--json", "example..com"},
			resolver:  noRecords,
			wantCode:  2,
			wantError: "Invalid domain:",
		},
		{
			name:      "unsupported record type",
			args:      []string{"--type", "INVALID", "--json", "example.com"},
			resolver:  noRecords,
			wantCode:  2,
			wantError: "Unsupported record type:",
		},
		{
			name:      "no records",
			args:      []string{"--json", "example.com"},
			resolver:  noRecords,
			wantCode:  1,
			wantError: "No A records found",
		},
		{
			name:      "lookup failure",
			args:      []string{"--json", "example.com"},
			resolver:  lookupError,
			wantCode:  1,
			wantError: "DNS lookup failed: DNS timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output, errorOutput bytes.Buffer

			code := cli.Run(
				tt.args,
				&output,
				&errorOutput,
				tt.resolver,
			)

			if code != tt.wantCode {
				t.Errorf("expected exit code %d, got %d",
					tt.wantCode, code)
			}

			if !strings.Contains(errorOutput.String(), tt.wantError) {
				t.Errorf("expected error containing %q, got %q",
					tt.wantError, errorOutput.String())
			}

			if output.Len() != 0 {
				t.Errorf("unexpected output: %q", output.String())
			}
		})
	}
}

func TestRunJSONOutputFailure(t *testing.T) {
	var errorOutput bytes.Buffer

	resolver := mockResolver{
		lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}

	code := cli.Run(
		[]string{"--json", "example.com"},
		failingWriter{},
		&errorOutput,
		resolver,
	)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}

	expected := "Output failed: write failed\n"
	if errorOutput.String() != expected {
		t.Errorf("expected %q, got %q",
			expected, errorOutput.String())
	}
}
