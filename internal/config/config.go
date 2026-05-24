package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Tencent struct {
	SecretID  string `yaml:"secret_id"`
	SecretKey string `yaml:"secret_key"`
	Region    string `yaml:"region"`
}

type Lighthouse struct {
	InstanceID string `yaml:"instance_id"`
}

type CVM struct {
	SecurityGroupID string `yaml:"security_group_id"`
}

type IPCheck struct {
	URLs            []string `yaml:"urls"`
	IntervalSeconds int      `yaml:"interval_seconds"`
}

type fileConfig struct {
	Tencent         Tencent   `yaml:"tencent"`
	Backend         string    `yaml:"backend"`
	Lighthouse      Lighthouse `yaml:"lighthouse"`
	CVM             CVM       `yaml:"cvm"`
	Ports           yamlPorts `yaml:"ports"`
	Protocol        string    `yaml:"protocol"`
	RuleDescription string    `yaml:"rule_description"`
	RemoveOldIP     *bool     `yaml:"remove_old_ip"`
	IPCheck         IPCheck   `yaml:"ip_check"`
	StateFile       string    `yaml:"state_file"`
}

// yamlPorts accepts either a YAML list or a comma-separated string.
type yamlPorts []string

func (p *yamlPorts) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		return nil
	}
	switch value.Kind {
	case yaml.ScalarNode:
		*p = splitPorts(value.Value)
		return nil
	case yaml.SequenceNode:
		var ports []string
		if err := value.Decode(&ports); err != nil {
			return err
		}
		*p = ports
		return nil
	default:
		return fmt.Errorf("ports: unsupported YAML kind %d", value.Kind)
	}
}

type Config struct {
	Tencent              Tencent
	Backend              string
	LighthouseInstanceID string
	SecurityGroupID      string
	Ports                []string
	Protocol             string
	RuleDescription      string
	RemoveOldIP          bool
	IPCheckURLs          []string
	IntervalSeconds      int
	StateFile            string
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw fileConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	secretID := envOr(raw.Tencent.SecretID, "TENCENT_SECRET_ID")
	secretKey := envOr(raw.Tencent.SecretKey, "TENCENT_SECRET_KEY")
	region := envOr(raw.Tencent.Region, "TENCENT_REGION")
	if secretID == "" || secretKey == "" || region == "" {
		return nil, fmt.Errorf("请在 config.yaml 或环境变量中配置 tencent.secret_id / secret_key / region")
	}

	backend := strings.ToLower(strings.TrimSpace(raw.Backend))
	if backend == "" {
		backend = "lighthouse"
	}
	if backend != "lighthouse" && backend != "cvm" {
		return nil, fmt.Errorf("backend 仅支持 lighthouse 或 cvm")
	}

	instanceID := envOr(raw.Lighthouse.InstanceID, "LIGHTHOUSE_INSTANCE_ID")
	sgID := envOr(raw.CVM.SecurityGroupID, "SECURITY_GROUP_ID")
	if backend == "lighthouse" && instanceID == "" {
		return nil, fmt.Errorf("lighthouse 模式需要配置 lighthouse.instance_id")
	}
	if backend == "cvm" && sgID == "" {
		return nil, fmt.Errorf("cvm 模式需要配置 cvm.security_group_id")
	}

	ports := []string(raw.Ports)
	if len(ports) == 0 {
		ports = []string{"22"}
	}

	urls := raw.IPCheck.URLs
	if len(urls) == 0 {
		urls = []string{
			"https://ddns.oray.com/checkip",
			"https://4.ipw.cn",
		}
	}

	interval := raw.IPCheck.IntervalSeconds
	if interval <= 0 {
		interval = 300
	}

	stateFile := raw.StateFile
	if stateFile == "" {
		stateFile = "~/.cache/FirewallKeeper/state.json"
	}
	stateFile = expandHome(stateFile)

	removeOld := true
	if raw.RemoveOldIP != nil {
		removeOld = *raw.RemoveOldIP
	}

	protocol := strings.ToUpper(strings.TrimSpace(raw.Protocol))
	if protocol == "" {
		protocol = "TCP"
	}

	desc := raw.RuleDescription
	if desc == "" {
		desc = "auto-ddns-whitelist"
	}

	return &Config{
		Tencent: Tencent{
			SecretID:  secretID,
			SecretKey: secretKey,
			Region:    region,
		},
		Backend:              backend,
		LighthouseInstanceID: instanceID,
		SecurityGroupID:      sgID,
		Ports:                ports,
		Protocol:             protocol,
		RuleDescription:      desc,
		RemoveOldIP:          removeOld,
		IPCheckURLs:          urls,
		IntervalSeconds:      interval,
		StateFile:            stateFile,
	}, nil
}

func envOr(value, envName string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func splitPorts(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
