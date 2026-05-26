package hetznercloud

import "testing"

func TestRuleMatchesInbound(t *testing.T) {
	r := Rule{
		Direction: "in",
		Protocol:  "tcp",
		Port:      "22",
		SourceIPs: []string{"1.2.3.4/32"},
	}
	if !ruleMatchesInbound(r, "tcp", "22", "1.2.3.4/32") {
		t.Fatal("expected match")
	}
	if ruleMatchesInbound(r, "tcp", "443", "1.2.3.4/32") {
		t.Fatal("expected no match on port")
	}
}
