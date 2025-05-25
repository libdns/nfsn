// Package nfsn implements a DNS record management client compatible with the libdns interfaces for
// nearlyfreespeech.net (NFSN)
package nfsn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

const apiBase = "https://api.nearlyfreespeech.net"
const authHeader = "X-NFSN-Authentication"

// NFSN enforces a minimum TTL of 3 minutes
const minimumTTL = 180 * time.Second

// Constants used for API salt generation
const saltChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijjklmnopqrstuvwxyz0123456789"
const saltLen = 16

// Provider facilitates DNS record manipulation with nearlyfreespeech.net
type Provider struct {
	// NFSN Member Login.
	Login string `json:"login,omitempty"`

	// NFSN API Key. API Keys can be generated from the "Profile" tab in the NFSN member interface.
	APIKey string `json:"api_key,omitempty"`

	client    *http.Client
	clientMtx sync.Mutex
}

type nfsnRecord struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Data  string `json:"data,omitempty"`
	TTL   int    `json:"ttl,omitempty"`
	Scope string `json:"scope,omitempty"`
	Aux   int    `json:"aux,omitempty"`
}

// The pieces necessary to make a request to create/update a record in NFSN. Differs slightly from
// the fields in libdns.Record - should re-test "aux" field not obvious it still exists...
type nfsnRecordParameters struct {
	Name string
	Type string
	Data string
	TTL  int
}

func (nRecord nfsnRecord) record() (libdns.Record, error) {
	switch nRecord.Type {
	case "A":
		fallthrough
	case "AAAA":
		addr, err := netip.ParseAddr(nRecord.Data)

		if err != nil {
			return libdns.RR{}, err
		}

		return libdns.Address{
			Name: nameForLibdns(nRecord.Name),
			IP:   addr,
			TTL:  time.Second * time.Duration(nRecord.TTL),
		}, nil
	case "CNAME":
		return libdns.CNAME{
			Name:   nameForLibdns(nRecord.Name),
			Target: nRecord.Data,
			TTL:    time.Second * time.Duration(nRecord.TTL),
		}, nil
	case "NS":
		return libdns.NS{
			Name:   nameForLibdns(nRecord.Name),
			Target: nRecord.Data,
			TTL:    time.Second * time.Duration(nRecord.TTL),
		}, nil
	case "PTR":
		// libdns doesn't have a PTR type so return an RR directly
		return libdns.RR{
			Type: "PTR",
			Name: nameForLibdns(nRecord.Name),
			Data: nRecord.Data,
			TTL:  time.Second * time.Duration(nRecord.TTL),
		}, nil
	case "MX":
		return libdns.MX{
			Name:       nameForLibdns(nRecord.Name),
			Target:     nRecord.Data,
			TTL:        time.Second * time.Duration(nRecord.TTL),
			Preference: uint16(nRecord.Aux),
		}, nil
	case "TXT":
		return libdns.TXT{
			Name: nameForLibdns(nRecord.Name),
			Text: nRecord.Data,
			TTL:  time.Second * time.Duration(nRecord.TTL),
		}, nil
	case "SRV":
		// Name is "_SERVICE._TRANSPORT.NAME" - NFSN allows .NAME to be omitted in which case the record
		// is for the zone domain name. If .NAME is omitted, libdns expects the value "@". libdns also
		// expects the service and transport values to omit the preceding '_' characters.
		nameFields := strings.SplitN(nRecord.Name, ".", 3)

		if len(nameFields) < 2 {
			return libdns.RR{}, fmt.Errorf("Name value '%s' has too few fields, expected at least 2", nRecord.Name)
		}

		name := "@"

		if len(nameFields) == 3 && nameFields[2] != "" {
			name = nameFields[2]
		}

		// Data is "WEIGHT PORT TARGET", the priority is in the Aux field.
		dataFields := strings.Fields(nRecord.Data)

		if len(dataFields) != 3 {
			return libdns.RR{}, fmt.Errorf("Data value '%s' has wrong number of fields, expected 3", nRecord.Data)
		}

		weight, err := strconv.ParseUint(dataFields[0], 10, 16)

		if err != nil {
			return libdns.RR{}, err
		}

		port, err := strconv.ParseUint(dataFields[1], 10, 16)

		if err != nil {
			return libdns.RR{}, err
		}

		return libdns.SRV{
			Service:   strings.TrimPrefix(nameFields[0], "_"),
			Transport: strings.TrimPrefix(nameFields[1], "_"),
			Name:      name,
			TTL:       time.Second * time.Duration(nRecord.TTL),
			Priority:  uint16(nRecord.Aux),
			Weight:    uint16(weight),
			Port:      uint16(port),
			Target:    dataFields[2],
		}, nil
	default:
		return libdns.RR{}, fmt.Errorf("Unsupported record type %s", nRecord.Type)
	}
}

func nameForLibdns(nfsName string) string {
	if nfsName == "" {
		return "@"
	}

	return nfsName
}

func nameForNfsn(libdnsName string) string {
	if libdnsName == "@" {
		return ""
	}

	return libdnsName
}

func ttlForNfsn(libdnsTtl time.Duration) string {
	ttl := libdnsTtl

	if ttl < minimumTTL {
		ttl = minimumTTL
	}

	return fmt.Sprintf("%d", int(ttl.Seconds()))
}

func innerToNfsnRecordParameters(record libdns.Record) (url.Values, error) {
	switch r := record.(type) {
	case libdns.Address:
		parameters := url.Values{}

		if r.IP.Is4() {
			parameters.Set("type", "A")
		} else {
			parameters.Set("type", "AAAA")
		}

		parameters.Set("name", nameForNfsn(r.Name))
		parameters.Set("data", r.IP.String())
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	case libdns.CNAME:
		parameters := url.Values{}
		parameters.Set("type", "CNAME")
		parameters.Set("name", nameForNfsn(r.Name))
		parameters.Set("data", r.Target)
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	case libdns.MX:
		parameters := url.Values{}
		parameters.Set("type", "MX")
		parameters.Set("name", nameForNfsn(r.Name))
		parameters.Set("data", r.Target)
		parameters.Set("aux", fmt.Sprintf("%d", r.Preference))
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	case libdns.NS:
		parameters := url.Values{}
		parameters.Set("type", "NS")
		parameters.Set("name", nameForNfsn(r.Name))
		parameters.Set("data", r.Target)
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	case libdns.SRV:
		parameters := url.Values{}
		parameters.Set("type", "SRV")

		name := nameForNfsn(r.Name)

		if name != "" {
			// Prepend with '.' so that the name parameter becomes "_SERVICE._TRANSPORT.NAME"
			name = fmt.Sprintf(".%s", name)
		}

		parameters.Set("name", fmt.Sprintf("_%s._%s%s", r.Service, r.Transport, name))

		// Data is "WEIGHT PORT TARGET"
		parameters.Set("data", fmt.Sprintf("%d %d %s", r.Weight, r.Port, r.Target))
		parameters.Set("aux", fmt.Sprintf("%d", r.Priority))
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	case libdns.TXT:
		parameters := url.Values{}
		parameters.Set("type", "TXT")
		parameters.Set("name", nameForNfsn(r.Name))
		parameters.Set("data", r.Text)
		parameters.Set("ttl", ttlForNfsn(r.TTL))
		return parameters, nil
	default:
		// libdns doesn't have a PTR type but NFSN supports it
		if r.RR().Type == "PTR" {
			parameters := url.Values{}
			parameters.Set("type", "PTR")
			parameters.Set("name", nameForNfsn(r.RR().Name))
			parameters.Set("data", r.RR().Data)
			parameters.Set("ttl", ttlForNfsn(r.RR().TTL))
			return parameters, nil
		}
		return url.Values{}, fmt.Errorf("Unsupported record type %s", r.RR().Type)
	}
}

func toNfsnRecordParameters(record libdns.Record) (url.Values, error) {
	switch r := record.(type) {
	case libdns.RR:
		rr, err := r.Parse()

		if err != nil {
			return url.Values{}, err
		}

		return innerToNfsnRecordParameters(rr)
	default:
		return innerToNfsnRecordParameters(r)
	}
}

// var dataBuilder strings.Builder

// TODO FIXME

/*
		switch record.Type {
		case "HTTPS":
		case "MX":
			dataBuilder.WriteString(fmt.Sprintf("%d ", record.Priority))
		case "SRV":
		case "URI":
			dataBuilder.WriteString(fmt.Sprintf("%d %d ", record.Priority, record.Weight))
		}

		dataBuilder.WriteString(record.Value)

		parameters := url.Values{}
		parameters.Set("name", record.Name)
		parameters.Set("type", record.Type)
		parameters.Set("data", dataBuilder.String())

		ttl := record.TTL

	 	if ttl < minimumTTL {
			ttl = minimumTTL
		}

		parameters.Set("ttl", fmt.Sprintf("%d", int(ttl.Seconds())))

		return parameters
*/

// Constructs a value to pass into an X-NFSN-Authentication header.
//
// The header value has the format [LOGIN];[TIMESTAMP];[SALT];[HASH]
//
// * LOGIN is the member's login name
// * TIMESTAMP is a 32 bit unsigned unix timestamp
// * SALT is a random, 16 character, alphanumeric string
// * HASH is sha1("[LOGIN];[TIMESTAMP];[SALT];[API_KEY];[REQUEST_URI];[BODY_HASH]")
//   - LOGIN, TIMESTAMP, SALT are the same as above
//   - API_KEY is the member's private API key
//   - REQUEST_URI is the PATH portion of the request URI
//   - BODY_HASH is the SHA1 hash of the request body (or of the empty string, if no request body is
//     present)
//
// Takes `timestamp` and `salt` values for testing.
func (p *Provider) innerGetAuthValue(req *http.Request, timestamp time.Time, salt string) (string, error) {
	var bodyBytes []byte
	var err error

	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)

		if err != nil {
			return "", err
		}
	}

	// Restore the body so it can be read again later
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	bodyHash := sha1.Sum(bodyBytes)

	// Build the text to hash
	hText := fmt.Sprintf("%s;%d;%s;%s;%s;%x", p.Login, timestamp.Unix(), salt, p.APIKey, req.URL.Path, bodyHash)
	hHash := sha1.Sum([]byte(hText))

	// Format the auth value to send on the wire
	authVal := fmt.Sprintf("%s;%d;%s;%x", p.Login, timestamp.Unix(), salt, hHash)
	return authVal, nil
}

// Generate a random salt usable for generating an X-NFSN-Authentication header value. See
// `innerGetAuthValue` for details.
func genSalt() (string, error) {
	bytes := make([]byte, saltLen)
	readLen, err := rand.Read(bytes)

	if err != nil {
		return "", err
	}

	if readLen != saltLen {
		return "", fmt.Errorf("Failed to read enough random bytes")
	}

	var sb strings.Builder

	for b := range bytes {
		sb.WriteByte(saltChars[b%len(saltChars)])
	}

	return sb.String(), nil
}

func uriForZone(zone string, resource string) string {
	return fmt.Sprintf("%s/dns/%s/%s", apiBase, strings.TrimRight(zone, "."), resource)
}

// See `innerGetAuthValue` for details.
func (p *Provider) getAuthValue(req *http.Request) (string, error) {
	salt, err := genSalt()

	if err != nil {
		return "", err
	}

	return p.innerGetAuthValue(req, time.Now(), salt)
}

func (p *Provider) ensureClient() {
	if p.client == nil {
		p.clientMtx.Lock()
		defer p.clientMtx.Unlock()

		if p.client == nil {
			p.client = &http.Client{}
		}
	}
}

// Makes a request with the given parameters (see `http.NewRequestWithContext`), adding necessary
// auth information before executing it.
func (p *Provider) makeRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Response, error) {
	p.ensureClient()
	req, err := http.NewRequestWithContext(ctx, method, url, body)

	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	authValue, err := p.getAuthValue(req)

	if err != nil {
		return nil, err
	}

	req.Header.Add(authHeader, authValue)

	resp, err := p.client.Do(req)

	if err != nil {
		return nil, err
	}

	var bodyBytes []byte

	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned non-success status code %s with response body %s. Original error: %w", resp.Status, string(bodyBytes), err)
	}

	return resp, err
}

// Execute the given `verb` for each record in `records`. Accumulate successfully processed records
// and return them at the end. If only some records are processed, returns those that were
// successfull _and_ an error.
func (p *Provider) processRecords(ctx context.Context, zone string, verb string, records []libdns.Record) ([]libdns.Record, error) {
	uri := uriForZone(zone, verb)
	var successfulRecords []libdns.Record

	for _, record := range records {
		// TODO consider doing all this up front so that invalid records are caught before mutation
		params, err := toNfsnRecordParameters(record)

		if err != nil {
			return successfulRecords, err
		}

		_, err = p.makeRequest(ctx, "POST", uri, strings.NewReader(params.Encode()))

		if err != nil {
			return successfulRecords, err
		}

		successfulRecords = append(successfulRecords, record)
	}

	return successfulRecords, nil
}

// See libdns.RecordGetter
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	resp, err := p.makeRequest(ctx, "POST", uriForZone(zone, "listRRs"), nil)

	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	var nRecords []nfsnRecord
	err = json.Unmarshal(bodyBytes, &nRecords)

	if err != nil {
		return nil, err
	}

	records := make([]libdns.Record, 0, len(nRecords))

	for _, nRecord := range nRecords {
		record, err := nRecord.record()

		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	return records, nil
}

// See libdns.RecordAppender
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.processRecords(ctx, zone, "addRR", records)
}

// See libdns.RecordSetter
//
// NFSN does not support atomic zone modification, so after computing the operations to perform each
// one will be attempted serially. In the case where only some operations succeed, returns both the
// records that were set (if any) and an error.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// FIXME Should be one replaceRR followed by any number of addRR requests for each (name, type) pair
	return p.processRecords(ctx, zone, "replaceRR", records)
}

// See libdns.RecordDeleter
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.processRecords(ctx, zone, "removeRR", records)
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
