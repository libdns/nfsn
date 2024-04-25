package nfsn

import (
	"net/http"
	"testing"
	"time"
)

func TestGetAuthValue(t *testing.T) {
	p := Provider{
		Login: "testuser",
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
