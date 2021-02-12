package rfc2136

import (
	"context"
	"fmt"
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
	p.mutex.Lock()
	defer p.mutex.Unlock()

	c := p.makeClient()
	nameserver := p.normalizedNameserver()

	var appendedRecords []libdns.Record
	for _, record := range records {
		rr, err := rrFromRecord(zone, record)
		if err != nil {
			return appendedRecords, fmt.Errorf("failed to append record: %w", err)
		}

		rrs := []dns.RR{rr}

		msg := new(dns.Msg)
		msg.SetUpdate(zone)
		// TODO: We may also need to `msg.RemoveRRset(rrs)` here to clean up just in case
		msg.Insert(rrs)
		p.configureMessage(msg)

		reply, _, err := c.Exchange(msg, nameserver)
		if err != nil {
			return appendedRecords, fmt.Errorf("failed to append record, %w", err)
		}
		if reply != nil && reply.Rcode != dns.RcodeSuccess {
			return appendedRecords, fmt.Errorf("failed to append record, server replied %s", dns.RcodeToString[reply.Rcode])
		}

		appendedRecords = append(appendedRecords, record)
	}

	return appendedRecords, nil
}

// DeleteRecords deletes records from the zone and returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	c := p.makeClient()
	nameserver := p.normalizedNameserver()

	var deletedRecords []libdns.Record
	for _, record := range records {
		rr, err := rrFromRecord(zone, record)
		if err != nil {
			return deletedRecords, fmt.Errorf("failed to append record: %w", err)
		}

		rrs := []dns.RR{rr}

		msg := new(dns.Msg)
		msg.SetUpdate(zone)
		msg.Remove(rrs)
		p.configureMessage(msg)

		reply, _, err := c.Exchange(msg, nameserver)
		if err != nil {
			return deletedRecords, fmt.Errorf("failed to append record, %w", err)
		}
		if reply != nil && reply.Rcode != dns.RcodeSuccess {
			return deletedRecords, fmt.Errorf("failed to append record, server replied %s", dns.RcodeToString[reply.Rcode])
		}

		deletedRecords = append(deletedRecords, record)
	}

	return deletedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones, and returns the records that were updated.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	c := p.makeClient()
	nameserver := p.normalizedNameserver()

	var setRecords []libdns.Record
	for _, record := range records {
		rr, err := rrFromRecord(zone, record)
		if err != nil {
			return setRecords, fmt.Errorf("failed to append record: %w", err)
		}

		rrs := []dns.RR{rr}

		msg := new(dns.Msg)
		msg.SetUpdate(zone)
		msg.RemoveRRset(rrs)
		msg.Insert(rrs)
		p.configureMessage(msg)

		reply, _, err := c.Exchange(msg, nameserver)
		if err != nil {
			return setRecords, fmt.Errorf("failed to append record, %w", err)
		}
		if reply != nil && reply.Rcode != dns.RcodeSuccess {
			return setRecords, fmt.Errorf("failed to append record, server replied %s", dns.RcodeToString[reply.Rcode])
		}

		setRecords = append(setRecords, record)
	}

	return setRecords, nil
}

// Make a DNS client from the provider config
func (p *Provider) makeClient() *dns.Client {
	c := new(dns.Client)
	c.SingleInflight = true
	if len(p.TSIGKeyName) > 0 && len(p.TSIGSecret) > 0 {
		c.TsigSecret = map[string]string{dns.Fqdn(p.TSIGKeyName): p.TSIGSecret}
	}
	return c
}

// Configure the DNS message with TSIG if configured
func (p *Provider) configureMessage(msg *dns.Msg) {
	if len(p.TSIGKeyName) > 0 && len(p.TSIGSecret) > 0 {
		msg.SetTsig(
			dns.Fqdn(p.TSIGKeyName),
			dns.Fqdn(p.TSIGAlgorithm),
			300,
			time.Now().Unix(),
		)
	}
}

// Convert a zone + libdns record into a dns.RR
func rrFromRecord(zone string, record libdns.Record) (dns.RR, error) {
	header := dns.RR_Header{
		Name:   zone,
		Rrtype: dns.StringToType[record.Type],
		Class:  dns.ClassINET,
		Ttl:    uint32(record.TTL),
	}

	var rr dns.RR
	switch record.Type {
	case "A":
		rr := new(dns.A)
		rr.Hdr = header
		rr.A = net.IP(record.Value)
	case "AAAA":
		rr := new(dns.AAAA)
		rr.Hdr = header
		rr.AAAA = net.IP(record.Value)
	case "CNAME":
		rr := new(dns.CNAME)
		rr.Hdr = header
		rr.Target = record.Value
	case "MX":
		rr := new(dns.MX)
		rr.Hdr = header
		rr.Mx = record.Value
		// TODO: How to we grab rr.Preference from libdns.Record?
	case "TXT":
		rr := new(dns.TXT)
		rr.Hdr = header
		rr.Txt = []string{record.Value}
	default:
		// Unsupported type, so we do nothing.
		// I couldn't find a simple way to support all the record types
		// dynamically, because each record has different fields to fill
		// to satisfy github.com/miekg/dns. Maybe we could use dns.NewRR()
		// if we can figure out a reliable way to construct the string.
		return nil, fmt.Errorf("unsupported type %s", record.Type)
	}

	return rr, nil
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
