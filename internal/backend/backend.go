package backend

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
)

type Backend interface {
	Name() string
	UpsertWhitelist(ip string, oldIP *string, cfg *config.Config) error
}

// NewAll 根据配置创建所有已启用的后端，可并行更新多个云厂商/实例。
func NewAll(cfg *config.Config) ([]Backend, error) {
	var backends []Backend
	for _, t := range cfg.Targets {
		b, err := newTarget(t, cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		backends = append(backends, b)
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("没有已启用的 targets")
	}
	return backends, nil
}

func newTarget(t config.Target, cfg *config.Config) (Backend, error) {
	switch t.Provider {
	case config.ProviderTencentLighthouse:
		return NewLighthouse(t, cfg)
	case config.ProviderTencentCVM:
		return NewCVM(t, cfg)
	case config.ProviderAliyunSWAS:
		return NewAliyunSWAS(t, cfg)
	case config.ProviderScalewaySG:
		return NewScalewaySG(t, cfg)
	case config.ProviderHetznerCloudFirewall:
		return NewHetznerCloud(t, cfg)
	case config.ProviderHetznerRobotFirewall:
		return NewHetznerRobot(t, cfg)
	case config.ProviderAWSLightsail:
		return NewAWSLightsail(t, cfg)
	case config.ProviderVolcengineSG:
		return NewVolcengineSG(t, cfg)
	case config.ProviderNetcupSCPFirewall:
		return NewNetcupFirewall(t, cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", t.Provider)
	}
}

// UpsertAll 依次更新所有后端；全部成功才返回 nil，否则返回聚合错误。
func UpsertAll(backends []Backend, ip string, oldIP *string, cfg *config.Config) error {
	var errs []error
	for _, b := range backends {
		logPrefix := fmt.Sprintf("[%s]", b.Name())
		if err := b.UpsertWhitelist(ip, oldIP, cfg); err != nil {
			errs = append(errs, fmt.Errorf("%s %w", logPrefix, err))
		}
	}
	return errors.Join(errs...)
}

func ruleDescription(cfg *config.Config, port string, maxLen int) string {
	desc := cfg.RuleDescription + ":" + port
	if len(desc) > maxLen {
		return desc[:maxLen]
	}
	return desc
}

// joinFirewallPorts 将多个端口合并为云厂商单条规则可用的 Port 字段（逗号分隔，最长 64）。
// 端口按字典序排序，便于与云端回读结果对齐；若超长则返回 ok=false，调用方应回退为逐端口规则。
func joinFirewallPorts(ports []string) (string, bool) {
	if len(ports) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "", false
	}
	sort.Strings(parts)
	joined := strings.Join(parts, ",")
	if len(joined) > 64 {
		return "", false
	}
	return joined, true
}

// sameFirewallPorts 比较两条 Port 字段是否表示同一组端口（忽略顺序）。
// 腾讯云 Describe 可能回传与 Create 不同的端口顺序，不能用字符串全等。
func sameFirewallPorts(a, b string) bool {
	if a == b {
		return true
	}
	norm := func(s string) []string {
		parts := strings.Split(s, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out
	}
	ap, bp := norm(a), norm(b)
	if len(ap) != len(bp) {
		return false
	}
	for i := range ap {
		if ap[i] != bp[i] {
			return false
		}
	}
	return true
}

func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exist") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "already") ||
		strings.Contains(msg, "已存在")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "notfound") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "不存在")
}

func isQuotaExceeded(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "limitexceeded") ||
		strings.Contains(msg, "quota") ||
		strings.Contains(msg, "firewallruleslimitexceeded")
}
