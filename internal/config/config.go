package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// 兼容旧版顶层字段（backend + tencent/lighthouse 等）
type Tencent struct {
	SecretID  string `yaml:"secret_id"`
	SecretKey string `yaml:"secret_key"`
	Region    string `yaml:"region"`
}

type Aliyun struct {
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"`
}

type Lighthouse struct {
	InstanceID string `yaml:"instance_id"`
}

type AliyunSWAS struct {
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
	Targets         map[string]targetYAML `yaml:"targets"`
	Backend         string                `yaml:"backend"` // 已废弃，兼容旧配置
	Tencent         Tencent               `yaml:"tencent"`
	Aliyun          Aliyun                `yaml:"aliyun"`
	Lighthouse      Lighthouse            `yaml:"lighthouse"`
	AliyunSWAS      AliyunSWAS            `yaml:"aliyun_swas"`
	CVM             CVM                   `yaml:"cvm"`
	Ports           yamlPorts             `yaml:"ports"`
	Protocol        string                `yaml:"protocol"`
	RuleDescription string                `yaml:"rule_description"`
	RemoveOldIP     *bool                 `yaml:"remove_old_ip"`
	IPCheck         IPCheck               `yaml:"ip_check"`
	StateFile       string                `yaml:"state_file"`
}

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

// Config 应用配置：Shared 为全局项，Targets 为可并行的多个厂商目标。
type Config struct {
	Ports           []string
	Protocol        string
	RuleDescription string
	RemoveOldIP     bool
	IPCheckURLs     []string
	IntervalSeconds int
	StateFile       string
	Targets         []Target
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

	targets, err := buildTargets(raw)
	if err != nil {
		return nil, err
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

	stateFile := envOr(raw.StateFile, "STATE_FILE")
	if stateFile == "" {
		stateFile = defaultStateFile()
	}
	stateFile = resolveStatePath(stateFile)

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
		Ports:           ports,
		Protocol:        protocol,
		RuleDescription: desc,
		RemoveOldIP:     removeOld,
		IPCheckURLs:     urls,
		IntervalSeconds: interval,
		StateFile:       stateFile,
		Targets:         targets,
	}, nil
}

func envOr(value, envName string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(os.Getenv(envName))
}

func defaultStateFile() string {
	if inDocker() {
		return "/data/state.json"
	}
	return "~/.cache/FirewallKeeper/state.json"
}

func resolveStatePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return defaultStateFile()
	}
	if strings.HasPrefix(path, "~/") {
		expanded := expandHome(path)
		if strings.HasPrefix(expanded, "~/") || isUnsafeContainerHomePath(expanded) {
			if inDocker() {
				return "/data/state.json"
			}
			return expanded
		}
		return expanded
	}
	return path
}

func inDocker() bool {
	if os.Getenv("DOCKER") == "1" {
		return true
	}
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func isUnsafeContainerHomePath(path string) bool {
	return strings.HasPrefix(path, "/.cache/") || path == "/.cache"
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	if home == "" {
		return path
	}
	return filepath.Join(home, path[2:])
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
