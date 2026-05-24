package state

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type fileState struct {
	LastIP string `json:"last_ip"`
}

func Load(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	var s fileState
	if err := json.Unmarshal(data, &s); err != nil {
		return "", nil
	}
	return s.LastIP, nil
}

func Save(path, ip string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileState{LastIP: ip}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
