package dns

// RecordType represents a DNS record type.
type RecordType string

const (
	RecordTypeA     RecordType = "A"
	RecordTypeAAAA  RecordType = "AAAA"
	RecordTypeMX    RecordType = "MX"
	RecordTypeNS    RecordType = "NS"
	RecordTypeTXT   RecordType = "TXT"
	RecordTypeCNAME RecordType = "CNAME"
)
