package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	snap := Snapshot{IP: "203.0.113.1", Ports: []string{"443", "22", "22"}}
	if err := Save(path, snap); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != snap.IP {
		t.Fatalf("IP = %q, want %q", got.IP, snap.IP)
	}
	if !PortsEqual(got.Ports, []string{"22", "443"}) {
		t.Fatalf("Ports = %v, want [22 443]", got.Ports)
	}
}

func TestLoadLegacyStateWithoutPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"last_ip":"203.0.113.1"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.IP != "203.0.113.1" {
		t.Fatalf("IP = %q", got.IP)
	}
	if len(got.Ports) != 0 {
		t.Fatalf("Ports = %v, want nil/empty", got.Ports)
	}
}

func TestPortsEqual(t *testing.T) {
	if !PortsEqual([]string{"22", "443"}, []string{"443", "22"}) {
		t.Fatal("expected equal ports")
	}
	if PortsEqual([]string{"22"}, []string{"22", "443"}) {
		t.Fatal("expected different ports")
	}
	if !PortsEqual(nil, []string{}) {
		t.Fatal("expected nil and empty to be equal")
	}
}
