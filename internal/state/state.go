package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fileState struct {
	LastIP    string   `json:"last_ip"`
	LastPorts []string `json:"last_ports,omitempty"`
}

type Snapshot struct {
	IP    string
	Ports []string
}

func Load(path string) (Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Snapshot{}, nil
		}
		return Snapshot{}, err
	}
	var s fileState
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}, nil
	}
	return Snapshot{IP: s.LastIP, Ports: s.LastPorts}, nil
}

func Save(path string, snap Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileState{
		LastIP:    snap.IP,
		LastPorts: NormalizePorts(snap.Ports),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func NormalizePorts(ports []string) []string {
	if len(ports) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ports))
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func PortsEqual(a, b []string) bool {
	na := NormalizePorts(a)
	nb := NormalizePorts(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}
