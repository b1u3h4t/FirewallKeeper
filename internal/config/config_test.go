package config

import "testing"

func TestResolveStatePathDockerFallback(t *testing.T) {
	t.Setenv("HOME", "/")
	t.Setenv("DOCKER", "")

	path := resolveStatePath("~/.cache/FirewallKeeper/state.json")
	if path != "/.cache/FirewallKeeper/state.json" {
		t.Fatalf("unexpected expanded path: %s", path)
	}

	t.Setenv("DOCKER", "1")
	path = resolveStatePath("~/.cache/FirewallKeeper/state.json")
	if path != "/data/state.json" {
		t.Fatalf("docker fallback want /data/state.json, got %s", path)
	}
}

func TestDefaultStateFileInDocker(t *testing.T) {
	t.Setenv("DOCKER", "1")
	if defaultStateFile() != "/data/state.json" {
		t.Fatalf("want /data/state.json in docker")
	}
	t.Setenv("DOCKER", "")
	if defaultStateFile() != "~/.cache/FirewallKeeper/state.json" {
		t.Fatalf("want local default outside docker")
	}
}
