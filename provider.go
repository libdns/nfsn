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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// TODO: Providers must not require additional provisioning steps by the callers; it should work
// simply by populating a struct and calling methods on it. If your DNS service requires long-lived
// state or some extra provisioning step, do it implicitly when methods are called; sync.Once can
// help with this, and/or you can use a sync.(RW)Mutex in your Provider struct to synchronize
// implicit provisioning.

// API format:
//
// GET/PUT/POST https://api.nearlyfreespeech.net/[NOUN]/[IDENTIFIER]/[VERB]

const apiBase = "https://api.nearlyfreespeech.net"
const authHeader = "X-NFSN-Authentication"

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

func (r nfsnRecord) Record() (libdns.Record, error) {
	lr := libdns.Record{
		Type:  r.Type,
		Name:  r.Name,
		Value: r.Data,
		TTL:   time.Second * time.Duration(r.TTL),
	}

	switch r.Type {
	case "HTTPS":
	case "MX":
		lr.Priority = uint(r.Aux)
	case "SRV":
	case "URI":
		// Priority is in the 'aux' field from NFSN
		lr.Priority = uint(r.Aux)

		// Data is "weight port target", libdns expects weight in the record
		parts := strings.SplitN(r.Data, " ", 2)

		if len(parts) != 3 {
			return libdns.Record{}, fmt.Errorf("%s record %s has incorrect format", r.Name, r.Data)
		}

		weight, err := strconv.Atoi(parts[0])

		if err != nil {
			return libdns.Record{}, err
		}

		lr.Weight = uint(weight)
		lr.Value = parts[1]
	}

	return lr, nil
}

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

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	// https://members.nearlyfreespeech.net/wiki/API/DNSListRRs
	// URI: /dns/[ZONE]/listRRs
	p.ensureClient()
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/dns/%s/listRRs", apiBase, zone), nil)

	if err != nil {
		return nil, err
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

	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	var nrs []nfsnRecord
	err = json.Unmarshal(bodyBytes, &nrs)

	if err != nil {
		return nil, err
	}

	rs := make([]libdns.Record, 0, len(nrs))

	for _, nr := range nrs {
		r, err := nr.Record()

		if err != nil {
			return nil, err
		}

		rs = append(rs, r)
	}

	return rs, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// https://members.nearlyfreespeech.net/wiki/API/DNSAddRR
	return nil, fmt.Errorf("TODO: not implemented")
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// https://members.nearlyfreespeech.net/wiki/API/DNSReplaceRR
	return nil, fmt.Errorf("TODO: not implemented")
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// https://members.nearlyfreespeech.net/wiki/API/DNSRemoveRR
	return nil, fmt.Errorf("TODO: not implemented")
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
