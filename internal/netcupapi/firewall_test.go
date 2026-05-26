package netcupapi

import "testing"

func TestRuleMatches(t *testing.T) {
	r := Rule{
		Direction:        "INGRESS",
		Protocol:         "TCP",
		Action:           "ACCEPT",
		Sources:          []string{"1.2.3.4/32"},
		DestinationPorts: portPtr("22"),
	}
	if !ruleMatches(r, "TCP", "22", "1.2.3.4/32") {
		t.Fatal("expected match")
	}
}
