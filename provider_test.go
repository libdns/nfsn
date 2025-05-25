package nfsn

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestGetAuthValue(t *testing.T) {
	p := Provider{
		Login:  "testuser",
		APIKey: "p3kxmRKf9dk3l6ls",
	}

	req, err := http.NewRequest("GET", "https://api.nearlyfreespeech.net/site/example/getInfo", nil)

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	ts := time.Unix(1012121212, 0)

	authVal, err := p.innerGetAuthValue(req, ts, "dkwo28Sile4jdXkw")

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	expected := "testuser;1012121212;dkwo28Sile4jdXkw;0fa8932e122d56e2f6d1550f9aab39c4aef8bfc4"

	if authVal != expected {
		t.Errorf("Expected '%s' but got '%s'", expected, authVal)
	}
}

func assertAddress(t *testing.T, record libdns.Record, name string, ip string, ttl int) {
	switch tr := record.(type) {
	case libdns.Address:
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.IP != netip.MustParseAddr(ip) {
			t.Errorf("Expected Addr '%s' but got %v", ip, tr.IP)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
		if tr.ProviderData != nil {
			t.Errorf("Expected nil ProviderData but got %v", tr.ProviderData)
		}
	default:
		t.Errorf("Expected an Address but got %v", tr)
	}
}

func assertCname(t *testing.T, record libdns.Record, name string, target string, ttl int) {
	switch tr := record.(type) {
	case libdns.CNAME:
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Target != target {
			t.Errorf("Expected Target '%s' but got %v", target, tr.Target)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
		if tr.ProviderData != nil {
			t.Errorf("Expected nil ProviderData but got %v", tr.ProviderData)
		}
	default:
		t.Errorf("Expected a CNAME but got %v", tr)
	}
}

func assertNs(t *testing.T, record libdns.Record, name string, target string, ttl int) {
	switch tr := record.(type) {
	case libdns.NS:
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Target != target {
			t.Errorf("Expected Target '%s' but got %v", target, tr.Target)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
		if tr.ProviderData != nil {
			t.Errorf("Expected nil ProviderData but got %v", tr.ProviderData)
		}
	default:
		t.Errorf("Expected a NS but got %v", tr)
	}
}

func assertMx(t *testing.T, record libdns.Record, name string, target string, preference int, ttl int) {
	switch tr := record.(type) {
	case libdns.MX:
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Target != target {
			t.Errorf("Expected Target '%s' but got %v", target, tr.Target)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
		if tr.Preference != uint16(preference) {
			t.Errorf("Expected preference %d but got %v", preference, tr.Preference)
		}
		if tr.ProviderData != nil {
			t.Errorf("Expected nil ProviderData but got %v", tr.ProviderData)
		}
	default:
		t.Errorf("Expected an MX but got %v", tr)
	}
}

func assertTxt(t *testing.T, record libdns.Record, name string, value string, ttl int) {
	switch tr := record.(type) {
	case libdns.TXT:
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Text != value {
			t.Errorf("Expected Text '%s' but got %v", value, tr.Text)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
		if tr.ProviderData != nil {
			t.Errorf("Expected nil ProviderData but got %v", tr.ProviderData)
		}
	default:
		t.Errorf("Expected a TXT but got %v", tr)
	}
}

func assertPtr(t *testing.T, record libdns.Record, name string, target string, ttl int) {
	switch tr := record.(type) {
	case libdns.RR:
		if tr.Type != "PTR" {
			t.Errorf("Expected Type 'PTR' but got %v", tr.Type)
		}
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Data != target {
			t.Errorf("Expected Target '%s' but got %v", target, tr.Data)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected %d second timeout but got %v", ttl, tr.TTL)
		}
	default:
		t.Errorf("Expected a PTR but got %v", tr)
	}
}

func assertSrv(
	t *testing.T,
	record libdns.Record,
	service string,
	transport string,
	name string,
	target string,
	priority int,
	weight int,
	port int,
	ttl int,
) {
	switch tr := record.(type) {
	case libdns.SRV:
		if tr.Service != service {
			t.Errorf("Expected Service '%s' but got %v", service, tr.Service)
		}
		if tr.Transport != transport {
			t.Errorf("Expected Transport '%s' but got %v", transport, tr.Transport)
		}
		if tr.Name != name {
			t.Errorf("Expected Name '%s' but got %v", name, tr.Name)
		}
		if tr.Target != target {
			t.Errorf("Expected Target '%s' but got %v", target, tr.Target)
		}
		if tr.Priority != uint16(priority) {
			t.Errorf("Expected Priority %d but got %v", priority, tr.Priority)
		}
		if tr.Weight != uint16(weight) {
			t.Errorf("Expected Weight %d but got %v", weight, tr.Weight)
		}
		if tr.Port != uint16(port) {
			t.Errorf("Expected Port %d but got %v", port, tr.Port)
		}
		if tr.TTL != time.Second*time.Duration(ttl) {
			t.Errorf("Expected TTL %d but got %v", ttl, tr.TTL)
		}
	default:
		t.Errorf("Expected an SRV but got %v", tr)
	}
}

func TestRecord(t *testing.T) {
	// A
	nRecord := nfsnRecord{
		Type: "A",
		Name: "",
		Data: "192.168.0.0",
		TTL:  300,
	}

	r, err := nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "@", "192.168.0.0", 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "test", "192.168.0.0", 300)

	// AAAA
	nRecord.Type = "AAAA"
	nRecord.Name = ""
	nRecord.Data = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "@", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "test", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", 300)

	// CNAME
	nRecord = nfsnRecord{
		Type: "CNAME",
		Name: "",
		Data: "www.test.com.",
		TTL:  300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertCname(t, r, "@", "www.test.com.", 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertCname(t, r, "test", "www.test.com.", 300)

	// NS
	nRecord = nfsnRecord{
		Type: "NS",
		Name: "",
		Data: "ns1.test.com",
		TTL:  300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertNs(t, r, "@", "ns1.test.com", 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertNs(t, r, "test", "ns1.test.com", 300)

	// PTR
	nRecord = nfsnRecord{
		Type: "PTR",
		Name: "",
		Data: "test.com",
		TTL:  300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertPtr(t, r, "@", "test.com", 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertPtr(t, r, "test", "test.com", 300)

	// MX
	nRecord = nfsnRecord{
		Type: "MX",
		Name: "",
		Data: "test.com",
		Aux:  10,
		TTL:  300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertMx(t, r, "@", "test.com", 10, 300)

	nRecord.Name = "test"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertMx(t, r, "test", "test.com", 10, 300)

	// SRV
	nRecord = nfsnRecord{
		Type: "SRV",
		Name: "_jabber._tcp",
		Data: "2 3 test.com.",
		// The NFSN API puts the priority in the `aux` field, everything else in the `data` field
		Aux: 1,
		TTL: 300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertSrv(t, r, "jabber", "tcp", "@", "test.com.", 1, 2, 3, 300)

	nRecord.Name = "_jabber._tcp.test.com"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertSrv(t, r, "jabber", "tcp", "test.com", "test.com.", 1, 2, 3, 300)

	nRecord.Name = ""

	r, err = nRecord.Record()

	if err == nil || !strings.Contains(err.Error(), "Name value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Name = "_jabber"

	r, err = nRecord.Record()

	if err == nil || !strings.Contains(err.Error(), "Name value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Name = "_jabber._tcp"
	nRecord.Data = "test.com"

	r, err = nRecord.Record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "1 test.com"

	r, err = nRecord.Record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "1 2 3 test.com"

	r, err = nRecord.Record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "-1 2 test.com"

	r, err = nRecord.Record()

	if err == nil {
		t.Errorf("Expected error from invalid SRV record")
	}

	nRecord.Data = "1 -2 test.com"

	r, err = nRecord.Record()

	if err == nil {
		t.Errorf("Expected error from invalid SRV record")
	}

	// TXT
	nRecord = nfsnRecord{
		Type: "TXT",
		Name: "",
		Data: "some text",
		TTL:  300,
	}

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertTxt(t, r, "@", "some text", 300)

	nRecord.Name = "_prefix"

	r, err = nRecord.Record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertTxt(t, r, "_prefix", "some text", 300)
}
