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

type Aliyun struct {
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"` // 可选，默认 swas.{region}.aliyuncs.com
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
	Tencent         Tencent    `yaml:"tencent"`
	Aliyun          Aliyun     `yaml:"aliyun"`
	Backend         string     `yaml:"backend"`
	Lighthouse      Lighthouse `yaml:"lighthouse"`
	AliyunSWAS      AliyunSWAS `yaml:"aliyun_swas"`
	CVM             CVM        `yaml:"cvm"`
	Ports           yamlPorts  `yaml:"ports"`
	Protocol        string     `yaml:"protocol"`
	RuleDescription string     `yaml:"rule_description"`
	RemoveOldIP     *bool      `yaml:"remove_old_ip"`
	IPCheck         IPCheck    `yaml:"ip_check"`
	StateFile       string     `yaml:"state_file"`
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
	Aliyun               Aliyun
	Backend              string
	LighthouseInstanceID string
	AliyunSWASInstanceID string
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

	backend := strings.ToLower(strings.TrimSpace(raw.Backend))
	if backend == "" {
		backend = "lighthouse"
	}

	tencent := Tencent{
		SecretID:  envOr(raw.Tencent.SecretID, "TENCENT_SECRET_ID"),
		SecretKey: envOr(raw.Tencent.SecretKey, "TENCENT_SECRET_KEY"),
		Region:    envOr(raw.Tencent.Region, "TENCENT_REGION"),
	}

	aliyun := Aliyun{
		AccessKeyID:     envOr(raw.Aliyun.AccessKeyID, "ALIBABA_CLOUD_ACCESS_KEY_ID"),
		AccessKeySecret: envOr(raw.Aliyun.AccessKeySecret, "ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
		Region:          envOr(raw.Aliyun.Region, "ALIBABA_CLOUD_REGION"),
		Endpoint:        envOr(raw.Aliyun.Endpoint, "ALIBABA_CLOUD_ENDPOINT"),
	}

	instanceID := envOr(raw.Lighthouse.InstanceID, "LIGHTHOUSE_INSTANCE_ID")
	aliyunInstanceID := envOr(raw.AliyunSWAS.InstanceID, "ALIBABA_CLOUD_SWAS_INSTANCE_ID")
	sgID := envOr(raw.CVM.SecurityGroupID, "SECURITY_GROUP_ID")

	switch backend {
	case "lighthouse", "cvm":
		if tencent.SecretID == "" || tencent.SecretKey == "" || tencent.Region == "" {
			return nil, fmt.Errorf("腾讯云后端需在 config.yaml 或环境变量中配置 tencent.secret_id / secret_key / region")
		}
	case "aliyun_swas":
		if aliyun.AccessKeyID == "" || aliyun.AccessKeySecret == "" || aliyun.Region == "" {
			return nil, fmt.Errorf("阿里云 SWAS 后端需在 config.yaml 或环境变量中配置 aliyun.access_key_id / access_key_secret / region")
		}
	default:
		return nil, fmt.Errorf("backend 仅支持 lighthouse、cvm、aliyun_swas")
	}

	if backend == "lighthouse" && instanceID == "" {
		return nil, fmt.Errorf("lighthouse 模式需要配置 lighthouse.instance_id")
	}
	if backend == "cvm" && sgID == "" {
		return nil, fmt.Errorf("cvm 模式需要配置 cvm.security_group_id")
	}
	if backend == "aliyun_swas" && aliyunInstanceID == "" {
		return nil, fmt.Errorf("aliyun_swas 模式需要配置 aliyun_swas.instance_id")
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
		Tencent:              tencent,
		Aliyun:               aliyun,
		Backend:              backend,
		LighthouseInstanceID: instanceID,
		AliyunSWASInstanceID: aliyunInstanceID,
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
