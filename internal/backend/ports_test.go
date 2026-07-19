package backend

import "testing"

func TestJoinFirewallPorts(t *testing.T) {
	got, ok := joinFirewallPorts([]string{"6000", "22", "443"})
	if !ok || got != "22,443,6000" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	got, ok = joinFirewallPorts([]string{"22,443"})
	if !ok || got != "22,443" {
		t.Fatalf("single multi-port entry: got %q ok=%v", got, ok)
	}
	long := make([]string, 40)
	for i := range long {
		long[i] = "60000"
	}
	if _, ok := joinFirewallPorts(long); ok {
		t.Fatal("expected too-long join to fail")
	}
}

func TestSameFirewallPorts(t *testing.T) {
	if !sameFirewallPorts("22,1022,443,5201,6000,6001,6002", "1022,22,443,5201,6000,6001,6002") {
		t.Fatal("same ports different order should match")
	}
	if sameFirewallPorts("22,443", "22,443,5201") {
		t.Fatal("different port sets should not match")
	}
}
