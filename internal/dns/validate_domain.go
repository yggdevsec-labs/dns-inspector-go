package dns

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maxDomainLength = 253
	maxLabelLength  = 63
)

// ValidateDomain checks whether a domain has a valid DNS name format.
// It accepts ASCII names, underscores, and an optional trailing dot.
func ValidateDomain(domain string) error {
	if strings.TrimSpace(domain) == "" {
		return errors.New("domain must not be empty")
	}

	name := strings.TrimSuffix(domain, ".")

	if len(name) == 0 || len(name) > maxDomainLength {
		return errors.New("invalid domain length")
	}

	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > maxLabelLength {
			return fmt.Errorf("invalid DNS label length: %q", label)
		}

		for i := 0; i < len(label); i++ {
			ch := label[i]

			valid := (ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '-' ||
				ch == '_'

			if !valid || (ch == '-' && (i == 0 || i == len(label)-1)) {
				return fmt.Errorf("invalid DNS label: %q", label)
			}
		}
	}

	return nil
}
