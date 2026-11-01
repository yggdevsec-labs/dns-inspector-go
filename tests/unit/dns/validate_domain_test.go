package dns_test

import (
	"strings"
	"testing"

	"github.com/yggdevsec-labs/dns-inspector-go/internal/dns"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:   "valid domain",
			domain: "example.com",
		},
		{
			name:   "uppercase domain",
			domain: "EXAMPLE.COM",
		},
		{
			name:   "subdomain",
			domain: "www.example.com",
		},
		{
			name:   "DNS label with underscore",
			domain: "_dmarc.example.com",
		},
		{
			name:   "hyphen inside label",
			domain: "my-domain.example.com",
		},
		{
			name:   "trailing dot",
			domain: "example.com.",
		},
		{
			name:   "maximum label length",
			domain: strings.Repeat("a", 63) + ".com",
		},
		{
			name: "maximum domain length",
			domain: strings.Join([]string{
				strings.Repeat("a", 63),
				strings.Repeat("b", 63),
				strings.Repeat("c", 63),
				strings.Repeat("d", 61),
			}, "."),
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			domain:  " \t ",
			wantErr: true,
		},
		{
			name:    "leading whitespace",
			domain:  " example.com",
			wantErr: true,
		},
		{
			name:    "empty label",
			domain:  "example..com",
			wantErr: true,
		},
		{
			name:    "leading dot",
			domain:  ".example.com",
			wantErr: true,
		},
		{
			name:    "multiple trailing dots",
			domain:  "example.com..",
			wantErr: true,
		},
		{
			name:    "leading hyphen",
			domain:  "-example.com",
			wantErr: true,
		},
		{
			name:    "trailing hyphen",
			domain:  "example-.com",
			wantErr: true,
		},
		{
			name:    "invalid character",
			domain:  "example!.com",
			wantErr: true,
		},
		{
			name:    "newline character",
			domain:  "example.com\n",
			wantErr: true,
		},
		{
			name:    "ANSI escape sequence",
			domain:  "evil\x1b[31m.com",
			wantErr: true,
		},
		{
			name:    "label too long",
			domain:  strings.Repeat("a", 64) + ".com",
			wantErr: true,
		},
		{
			name: "domain too long",
			domain: strings.Join([]string{
				strings.Repeat("a", 63),
				strings.Repeat("b", 63),
				strings.Repeat("c", 63),
				strings.Repeat("d", 62),
			}, "."),
			wantErr: true,
		},
		{
			name:    "root domain only",
			domain:  ".",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dns.ValidateDomain(tt.domain)

			if tt.wantErr && err == nil {
				t.Errorf("expected validation error for %q", tt.domain)
			}

			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}
