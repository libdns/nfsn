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

func TestARecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "A",
		Name: "",
		Data: "192.168.0.0",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "@", "192.168.0.0", 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "test", "192.168.0.0", 300)
}

func TestAAAARecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "AAAA",
		Name: "",
		Data: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "@", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertAddress(t, r, "test", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", 300)
}

func TestCNAMERecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "CNAME",
		Name: "",
		Data: "www.test.com.",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertCname(t, r, "@", "www.test.com.", 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertCname(t, r, "test", "www.test.com.", 300)
}

func TestNSRecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "NS",
		Name: "",
		Data: "ns1.test.com",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertNs(t, r, "@", "ns1.test.com", 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertNs(t, r, "test", "ns1.test.com", 300)
}

func TestPTRRecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "PTR",
		Name: "",
		Data: "test.com",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertPtr(t, r, "@", "test.com", 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertPtr(t, r, "test", "test.com", 300)
}

func TestMXRecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "MX",
		Name: "",
		Data: "test.com",
		Aux:  10,
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertMx(t, r, "@", "test.com", 10, 300)

	nRecord.Name = "test"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertMx(t, r, "test", "test.com", 10, 300)
}

func TestSRVRecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "SRV",
		Name: "_jabber._tcp",
		Data: "2 3 test.com.",
		// The NFSN API puts the priority in the `aux` field, everything else in the `data` field
		Aux: 1,
		TTL: 300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertSrv(t, r, "jabber", "tcp", "@", "test.com.", 1, 2, 3, 300)

	nRecord.Name = "_jabber._tcp.test.com"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertSrv(t, r, "jabber", "tcp", "test.com", "test.com.", 1, 2, 3, 300)

	nRecord.Name = ""

	r, err = nRecord.record()

	if err == nil || !strings.Contains(err.Error(), "Name value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Name = "_jabber"

	r, err = nRecord.record()

	if err == nil || !strings.Contains(err.Error(), "Name value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Name = "_jabber._tcp"
	nRecord.Data = "test.com"

	r, err = nRecord.record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "1 test.com"

	r, err = nRecord.record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "1 2 3 test.com"

	r, err = nRecord.record()

	if err == nil || !strings.Contains(err.Error(), "Data value") {
		t.Errorf("Expected error from invalid SRV record %v", err)
	}

	nRecord.Data = "-1 2 test.com"

	r, err = nRecord.record()

	if err == nil {
		t.Errorf("Expected error from invalid SRV record")
	}

	nRecord.Data = "1 -2 test.com"

	r, err = nRecord.record()

	if err == nil {
		t.Errorf("Expected error from invalid SRV record")
	}
}

func TestTXTRecord(t *testing.T) {
	nRecord := nfsnRecord{
		Type: "TXT",
		Name: "",
		Data: "some text",
		TTL:  300,
	}

	r, err := nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertTxt(t, r, "@", "some text", 300)

	nRecord.Name = "_prefix"

	r, err = nRecord.record()

	if err != nil {
		t.Errorf("Unexpected error %v", err)
	}

	assertTxt(t, r, "_prefix", "some text", 300)
}

func TestAParameters(t *testing.T) {
	addr, _ := netip.ParseAddr("192.168.0.0")

	r := libdns.Address{
		Name: "@",
		TTL:  time.Second * time.Duration(300),
		IP:   addr,
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "A" {
		t.Errorf("Expected type 'A' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "192.168.0.0" {
		t.Errorf("Expected data '192.168.0.0' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.Address{
		Name: "test",
		TTL:  time.Second * time.Duration(300),
		IP:   addr,
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "A" {
		t.Errorf("Expected type 'A' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "192.168.0.0" {
		t.Errorf("Expected data '192.168.0.0' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestCnameParameters(t *testing.T) {
	r := libdns.CNAME{
		Name:   "@",
		TTL:    time.Second * time.Duration(300),
		Target: "test.com",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "CNAME" {
		t.Errorf("Expected type 'CNAME' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.CNAME{
		Name:   "test",
		TTL:    time.Second * time.Duration(300),
		Target: "test.com",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "CNAME" {
		t.Errorf("Expected type 'CNAME' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestMxParameters(t *testing.T) {
	r := libdns.MX{
		Name:       "@",
		TTL:        time.Second * time.Duration(300),
		Preference: 10,
		Target:     "test.com",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "MX" {
		t.Errorf("Expected type 'MX' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if aux := params.Get("aux"); aux != "10" {
		t.Errorf("Expected aux '10' but got '%s'", aux)
	}

	if len(params) != 5 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.MX{
		Name:       "test",
		TTL:        time.Second * time.Duration(300),
		Preference: 10,
		Target:     "test.com",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "MX" {
		t.Errorf("Expected type 'MX' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if aux := params.Get("aux"); aux != "10" {
		t.Errorf("Expected aux '10' but got '%s'", aux)
	}

	if len(params) != 5 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestNsParameters(t *testing.T) {
	r := libdns.NS{
		Name:   "@",
		TTL:    time.Second * time.Duration(300),
		Target: "test.com",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "NS" {
		t.Errorf("Expected type 'NS' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.NS{
		Name:   "test",
		TTL:    time.Second * time.Duration(300),
		Target: "test.com",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "NS" {
		t.Errorf("Expected type 'NS' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestSrvParameters(t *testing.T) {
	r := libdns.SRV{
		Service:   "xmpp",
		Transport: "tcp",
		Name:      "@",
		TTL:       time.Second * time.Duration(300),
		Priority:  10,
		Weight:    20,
		Port:      30,
		Target:    "test.com",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "SRV" {
		t.Errorf("Expected type 'SRV' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "_xmpp._tcp" {
		t.Errorf("Expected name '_xmpp._tcp' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "20 30 test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if aux := params.Get("aux"); aux != "10" {
		t.Errorf("Expected aux '10' but got '%s'", aux)
	}

	if len(params) != 5 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.SRV{
		Service:   "xmpp",
		Transport: "tcp",
		Name:      "test",
		TTL:       time.Second * time.Duration(300),
		Priority:  10,
		Weight:    20,
		Port:      30,
		Target:    "test.com",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "SRV" {
		t.Errorf("Expected type 'SRV' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "_xmpp._tcp.test" {
		t.Errorf("Expected name '_xmpp._tcp' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "20 30 test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if aux := params.Get("aux"); aux != "10" {
		t.Errorf("Expected aux '10' but got '%s'", aux)
	}

	if len(params) != 5 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestTxtParameters(t *testing.T) {
	r := libdns.TXT{
		Name: "@",
		TTL:  time.Second * time.Duration(300),
		Text: "some text",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "TXT" {
		t.Errorf("Expected type 'TXT' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "some text" {
		t.Errorf("Expected data 'some text' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.TXT{
		Name: "test",
		TTL:  time.Second * time.Duration(300),
		Text: "some text",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "TXT" {
		t.Errorf("Expected type 'TXT' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "some text" {
		t.Errorf("Expected data 'some text' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}

func TestPtrParameters(t *testing.T) {
	r := libdns.RR{
		Type: "PTR",
		Name: "@",
		TTL:  time.Second * time.Duration(300),
		Data: "test.com",
	}

	params, err := toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "PTR" {
		t.Errorf("Expected type 'PTR' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "" {
		t.Errorf("Expected name '' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}

	r = libdns.RR{
		Type: "PTR",
		Name: "test",
		TTL:  time.Second * time.Duration(300),
		Data: "test.com",
	}

	params, err = toNfsnRecordParameters(r)

	if err != nil {
		t.Errorf("Expected no error but got %v", err)
	}

	if tp := params.Get("type"); tp != "PTR" {
		t.Errorf("Expected type 'PTR' but got '%s'", tp)
	}

	if name := params.Get("name"); name != "test" {
		t.Errorf("Expected name 'test' but got '%s'", name)
	}

	if ttl := params.Get("ttl"); ttl != "300" {
		t.Errorf("Expected ttl '300' but got '%s'", ttl)
	}

	if data := params.Get("data"); data != "test.com" {
		t.Errorf("Expected data 'test.com' but got '%s'", data)
	}

	if len(params) != 4 {
		t.Errorf("Params has incorrect number of fields, expected 4 %v", params)
	}
}
