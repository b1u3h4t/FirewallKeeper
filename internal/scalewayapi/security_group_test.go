package scalewayapi

import "testing"

func TestNormalizeCIDR(t *testing.T) {
	if got := normalizeCIDR("1.2.3.4"); got != "1.2.3.4/32" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeCIDR("1.2.3.4/32"); got != "1.2.3.4/32" {
		t.Fatalf("got %q", got)
	}
}

func TestPortMatches(t *testing.T) {
	from, to := uint32(22), uint32(22)
	if !portMatches(&from, &to, 22) {
		t.Fatal("expected match")
	}
	if portMatches(nil, nil, 22) {
		t.Fatal("expected no match for all ports vs 22")
	}
}

func TestParsePort(t *testing.T) {
	p, err := ParsePort("443")
	if err != nil || p != 443 {
		t.Fatalf("got %d %v", p, err)
	}
	p, err = ParsePort("6000-6010")
	if err != nil || p != 6000 {
		t.Fatalf("got %d %v", p, err)
	}
}
