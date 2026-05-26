package awsapi

import "testing"

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

func TestPortExists(t *testing.T) {
	states := []InstancePortState{{
		FromPort: 22, ToPort: 22, Protocol: "tcp",
		CIDRs: []string{"1.2.3.4/32"},
	}}
	c := &LightsailClient{}
	if !c.PortExists(states, "TCP", 22, "1.2.3.4/32") {
		t.Fatal("expected match")
	}
}
