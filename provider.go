package rfc2136

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

type Provider struct {
	// The address of the DNS server which supports RFC2136.
	Nameserver string `json:"nameserver,omitempty"`

	// The algorithm to use for TSIG.
	// See https://github.com/miekg/dns/blob/master/tsig.go for available modes.
	// The trailing dot is not required.
	TSIGAlgorithm string `json:"tsig_algorithm,omitempty"`

	// The key name used when generating the key.
	TSIGKeyName string `json:"tsig_keyname,omitempty"`

	// The secret used to compute the signature.
	TSIGSecret string `json:"tsig_secret,omitempty"`

	mutex sync.Mutex
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Do a DNS query for everything in the zone (ANY)
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{Name: zone, Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	in, err := dns.Exchange(msg, p.normalizedNameserver())
	if err != nil {
		return nil, err
	}

	// Collect the records
	fetchedRecords := []libdns.Record{}
	for _, record := range in.Answer {
		header := record.Header()
		fetchedRecords = append(fetchedRecords, libdns.Record{
			Name:  header.Name,
			Type:  dns.Type(header.Rrtype).String(),
			Value: record.String(),
			TTL:   time.Duration(header.Ttl),
		})
	}

	return fetchedRecords, nil
}

// AppendRecords adds records to the zone and returns the records that were created.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var appendedRecords []libdns.Record

	// TODO

	return appendedRecords, nil
}

// DeleteRecords deletes records from the zone and returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	// TODO

	return deletedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones, and returns the recordsthat were updated.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var setRecords []libdns.Record

	// TODO

	return setRecords, nil
}

// Append the default DNS port if none is specified.
func (p *Provider) normalizedNameserver() string {
	if _, _, err := net.SplitHostPort(p.Nameserver); err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return net.JoinHostPort(p.Nameserver, "53")
		}
	}
	return p.Nameserver
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
