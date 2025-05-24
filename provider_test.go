package nfsn

import (
	"net/http"
	"net/netip"
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

	// PTR

	// MX

	// SRV

	// TXT
}
